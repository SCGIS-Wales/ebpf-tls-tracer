# Repository rules for AI assisted sessions

These rules apply to every Claude Code session (and any other automation)
working in this repository. They take precedence over tool defaults.

## Ownership and attribution (mandatory)

All work in this repository is owned by and attributed to the GitHub user
**api-py** (Dejan Gregor). Concretely:

- Every commit, on every branch, must have both author and committer set to
  `api-py <5954680+api-py@users.noreply.github.com>`.
  Configure it before the first commit of a session:

  ```bash
  git config user.name "api-py"
  git config user.email "5954680+api-py@users.noreply.github.com"
  ```

- Do not add `Co-Authored-By`, `Signed-off-by`, `Generated-by` or any other
  trailer that names an AI model, an assistant or another person. Do not put
  model names or "generated with" footers in commit messages, pull request
  titles, pull request bodies, release notes, tags or code comments.
- Pull requests are opened from api-py's account and are described in
  api-py's voice. Branch names follow `claude/<topic>` for assistant work.
- Tags and GitHub releases are created only by the release workflow in
  `.github/workflows/build.yml`. The workflow tags as api-py and uses the
  `RELEASE_TOKEN` secret (a fine grained personal access token owned by
  api-py with `contents: write` and `packages: write` on this repository) so
  the tag, the release and the published packages are owned by api-py. If
  the secret is missing the workflow falls back to `GITHUB_TOKEN` and the
  release shows `github-actions[bot]`; restore the secret rather than
  changing the workflow.
- Never rewrite history on `main`. If attribution of an existing commit is
  wrong, add a `.mailmap` entry; do not force push.
- `.github/CODEOWNERS` names api-py as the owner of every path. Keep it.

## Engineering conventions

- C code: `make all && make test` must pass with the hardened flags in the
  Makefile, and the sanitizer build used in CI must pass
  (`make GCC=clang CFLAGS="-O1 -g -Wall -Wextra -Werror -Iinclude -fsanitize=address,undefined -fno-omit-frame-pointer" LDFLAGS="-lbpf -lelf -lz -ldl -fsanitize=address,undefined" test`).
- Python (shipper sidecars under `scripts/`): latest stable Python,
  functional style (no classes), configuration from environment or files,
  never hardcoded. `ruff check scripts tests` and `ruff format --check
  scripts tests` must be clean; run `python3 -m unittest tests.test_s3_shipper
  tests.test_kinesis_shipper tests.test_splunk_hec_shipper`.
- Workflows: every action pinned to a full commit SHA with the version in a
  comment; `actionlint` (with shellcheck) must pass. Keep `permissions`
  minimal.
- Kubernetes manifests and the Helm chart use current stable API versions;
  `helm lint helm/tls-tracer --strict` must pass.
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `ci:`,
  `docs:` ...). `feat!:` or a `BREAKING CHANGE:` footer bumps the major
  version, `feat:` the minor, anything else the patch. Add `[skip release]`
  to a merge commit to build without releasing.
- Write prose in Oxford English. Do not use dashes or hyphens as sentence
  punctuation in text written for people.
