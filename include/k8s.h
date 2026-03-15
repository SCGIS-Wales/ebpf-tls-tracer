#ifndef K8S_H
#define K8S_H

#include "tracer.h"
#include <sys/types.h>  /* pid_t */

/* K8s pod metadata extracted from /proc/<pid>/environ and /proc/<pid>/cgroup */
struct k8s_meta {
    char pod_name[256];
    char pod_namespace[256];
    char container_id[80];
};

/* Look up cached K8s metadata for a PID. Returns 1 if found, 0 if not. */
int k8s_cache_lookup(pid_t pid, struct k8s_meta *out);

/* Store K8s metadata in the cache for a PID. */
void k8s_cache_store(pid_t pid, const struct k8s_meta *meta);

/* Read K8s metadata for a PID with rate-limiting to prevent /proc I/O storms. */
void get_k8s_meta_ratelimited(pid_t pid, struct k8s_meta *meta);

#endif /* K8S_H */
