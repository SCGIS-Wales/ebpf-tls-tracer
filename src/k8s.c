// SPDX-License-Identifier: MIT
//
// Kubernetes metadata enrichment: reads pod name, namespace, and container ID
// from /proc/<pid>/environ and /proc/<pid>/cgroup. Caches results per PID
// with TTL to avoid repeated filesystem I/O.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include "k8s.h"

#define K8S_CACHE_SIZE     1024  /* max cached PID->k8s_meta entries (must be power of 2) */
#define K8S_CACHE_TTL      60    /* seconds before re-reading /proc */

/* Read an environment variable from /proc/<pid>/environ */
/* H-4 fix: Limit read to 4KB to reduce information exposure.
 * The tracer runs as root with hostPID:true and could read secrets from
 * other processes' environ. Bounded read limits the window. Uses raw
 * open/read instead of getdelim to avoid unbounded heap allocation. */
static int read_proc_env(pid_t pid, const char *var_name, char *buf, size_t buflen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/environ", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    char block[4096];
    ssize_t n = read(fd, block, sizeof(block) - 1);
    close(fd);
    if (n <= 0)
        return -1;
    block[n] = '\0';

    size_t var_len = strlen(var_name);
    char *p = block;
    char *end = block + n;
    while (p < end) {
        size_t entry_len = strnlen(p, (size_t)(end - p));
        if (entry_len > var_len && p[var_len] == '=' &&
            strncmp(p, var_name, var_len) == 0) {
            snprintf(buf, buflen, "%s", p + var_len + 1);
            return 0;
        }
        p += entry_len + 1;
    }
    return -1;
}

/* Extract container ID from /proc/<pid>/cgroup */
static int read_container_id(pid_t pid, char *buf, size_t buflen)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/cgroup", pid);
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        /* Look for containerd/docker cgroup paths:
         * .../docker-<id>.scope  or  .../cri-containerd-<id>.scope
         * or  .../pod<uid>/<container_id> */
        char *p;

        /* Pattern: cri-containerd- or docker- followed by hex ID */
        p = strstr(line, "cri-containerd-");
        if (!p)
            p = strstr(line, "docker-");
        if (p) {
            /* Skip prefix to get to the ID */
            char *id_start = strchr(p, '-');
            if (id_start) {
                id_start++;  /* skip second '-' for cri-containerd- */
                if (strncmp(p, "cri-containerd-", 15) == 0) {
                    id_start = p + 15;
                } else {
                    id_start = strchr(p, '-') + 1;
                }
                /* Copy up to .scope or end of line */
                char *end = strstr(id_start, ".scope");
                if (!end)
                    end = strchr(id_start, '\n');
                if (end) {
                    size_t id_len = (size_t)(end - id_start);
                    if (id_len > 12) id_len = 12;  /* short container ID */
                    snprintf(buf, buflen, "%.*s", (int)id_len, id_start);
                    fclose(f);
                    return 0;
                }
            }
        }

        /* Pattern: last path component is a hex container ID (64 chars) */
        p = strrchr(line, '/');
        if (p && strlen(p + 1) >= 64) {
            char *id = p + 1;
            /* Verify it looks like hex */
            int is_hex = 1;
            for (int i = 0; i < 12 && id[i]; i++) {
                if (!isxdigit((unsigned char)id[i])) {
                    is_hex = 0;
                    break;
                }
            }
            if (is_hex) {
                snprintf(buf, buflen, "%.12s", id);
                fclose(f);
                return 0;
            }
        }
    }

    fclose(f);
    return -1;
}

static void get_k8s_meta(pid_t pid, struct k8s_meta *meta)
{
    memset(meta, 0, sizeof(*meta));

    /* Pod name and namespace are typically set by K8s downward API:
     * POD_NAME, POD_NAMESPACE, or HOSTNAME for pod name */
    if (read_proc_env(pid, "POD_NAME", meta->pod_name, sizeof(meta->pod_name)) != 0)
        read_proc_env(pid, "HOSTNAME", meta->pod_name, sizeof(meta->pod_name));

    read_proc_env(pid, "POD_NAMESPACE", meta->pod_namespace, sizeof(meta->pod_namespace));
    read_container_id(pid, meta->container_id, sizeof(meta->container_id));
}

/* --- R-3 fix: K8s metadata cache per PID ---
 * Avoids reading /proc/<pid>/environ and /proc/<pid>/cgroup on every
 * single TLS event. Pod metadata doesn't change during a process's lifetime,
 * so we cache it with a TTL for safety (handles PID reuse). */
struct k8s_cache_entry {
    pid_t  pid;
    time_t last_seen;
    struct k8s_meta meta;
    __u8   valid;
};

static struct k8s_cache_entry k8s_cache_table[K8S_CACHE_SIZE];

static inline __u32 k8s_hash(pid_t pid)
{
    return ((__u32)pid * 2654435761u) & (K8S_CACHE_SIZE - 1);
}

int k8s_cache_lookup(pid_t pid, struct k8s_meta *out)
{
    time_t now = time(NULL);
    __u32 idx = k8s_hash(pid);
    for (__u32 i = 0; i < K8S_CACHE_SIZE; i++) {
        __u32 slot = (idx + i) & (K8S_CACHE_SIZE - 1);
        if (!k8s_cache_table[slot].valid)
            return 0;
        if (k8s_cache_table[slot].pid == pid) {
            if (now - k8s_cache_table[slot].last_seen > K8S_CACHE_TTL) {
                k8s_cache_table[slot].valid = 0;
                return 0;
            }
            *out = k8s_cache_table[slot].meta;
            return 1;
        }
    }
    return 0;
}

void k8s_cache_store(pid_t pid, const struct k8s_meta *meta)
{
    time_t now = time(NULL);
    __u32 idx = k8s_hash(pid);
    for (__u32 i = 0; i < K8S_CACHE_SIZE; i++) {
        __u32 slot = (idx + i) & (K8S_CACHE_SIZE - 1);
        if (!k8s_cache_table[slot].valid || k8s_cache_table[slot].pid == pid) {
            k8s_cache_table[slot].pid = pid;
            k8s_cache_table[slot].last_seen = now;
            k8s_cache_table[slot].meta = *meta;
            k8s_cache_table[slot].valid = 1;
            return;
        }
        if (now - k8s_cache_table[slot].last_seen > K8S_CACHE_TTL) {
            k8s_cache_table[slot].pid = pid;
            k8s_cache_table[slot].last_seen = now;
            k8s_cache_table[slot].meta = *meta;
            k8s_cache_table[slot].valid = 1;
            return;
        }
    }
    /* Table full — overwrite hash index */
    k8s_cache_table[idx].pid = pid;
    k8s_cache_table[idx].last_seen = now;
    k8s_cache_table[idx].meta = *meta;
    k8s_cache_table[idx].valid = 1;
}

/* M-3 fix: Rate-limited wrapper for get_k8s_meta to prevent /proc I/O storm
 * under high PID churn (e.g. Kubernetes Jobs, CronJobs, init containers). */
#define MAX_PROC_READS_PER_SEC 50
static time_t last_proc_read_sec = 0;
static int proc_reads_this_sec = 0;

void get_k8s_meta_ratelimited(pid_t pid, struct k8s_meta *meta)
{
    time_t now = time(NULL);
    if (now != last_proc_read_sec) {
        last_proc_read_sec = now;
        proc_reads_this_sec = 0;
    }
    if (proc_reads_this_sec >= MAX_PROC_READS_PER_SEC) {
        memset(meta, 0, sizeof(*meta));
        return;
    }
    proc_reads_this_sec++;
    get_k8s_meta(pid, meta);
}
