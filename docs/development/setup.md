# Development environment setup

This document covers the optional but recommended developer-side
tooling that accelerates local iteration. None of it is required to
contribute (CI is the authoritative gate); all of it makes
contribution faster and surfaces failures earlier.

## Required

- **Go 1.22+** (we test on 1.22; 1.23 works)
- **bash** for the various shell scripts
- **Make** for the canonical build entry points

## Recommended

| Tool                | Purpose                                               | Install                                                              |
|---------------------|-------------------------------------------------------|-----------------------------------------------------------------------|
| `golangci-lint`     | Static lint (gosec, errcheck, ineffassign, …)         | https://golangci-lint.run/usage/install/                              |
| `govulncheck`       | Upstream CVE scan against go.mod                      | `go install golang.org/x/vuln/cmd/govulncheck@latest`                |
| `benchstat`         | Compare two `go test -bench` runs statistically       | `go install golang.org/x/perf/cmd/benchstat@latest`                  |
| `go-mutesting`      | Mutation testing (weekly CI; on-demand local)         | `go install github.com/avito-tech/go-mutesting/cmd/go-mutesting@latest` |
| `syft`              | Generate SBOM (release-time; preview locally)         | `curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh \| sh -s -- -b /usr/local/bin` |
| `cosign`            | Verify release-binary signatures                      | `go install github.com/sigstore/cosign/v2/cmd/cosign@latest`         |
| `pre-commit`        | Run hooks at commit time (see below)                  | `pip install pre-commit` (or `brew install pre-commit`)              |
| `gitleaks`          | Block hard-coded secrets at commit                    | `brew install gitleaks` (macOS) / per-distro instructions             |

## Pre-commit hooks

`.pre-commit-config.yaml` at the repo root configures the
[pre-commit](https://pre-commit.com/) framework to run a strict
subset of CI checks on every `git commit`. To enable:

```bash
pip install pre-commit          # or `brew install pre-commit`
pre-commit install              # one-time, sets up .git/hooks/pre-commit
pre-commit run --all-files      # run on full tree to validate setup
```

Hooks run on the staged files only; the full-tree check is for first-time
validation. After install, every `git commit` triggers the hooks; the
commit is blocked on any failure.

To bypass once (not recommended — CI will fail on the same check anyway):

```bash
git commit --no-verify -m "WIP"
```

## .editorconfig

`.editorconfig` at the repo root configures every modern editor (VS Code,
JetBrains IDEs, Vim with editorconfig-vim plugin, Emacs with editorconfig
package) to use the project's whitespace + line-ending conventions:

- UTF-8, LF line endings, final newline, trim trailing whitespace
- `.go`: tab indent
- `.yml`/`.yaml`/`.json`/`.md`/`.sh`: 2-space indent
- `Makefile`: tab indent (Make requires it)

Most editors detect `.editorconfig` automatically. VS Code requires
the [editorconfig extension](https://marketplace.visualstudio.com/items?itemName=EditorConfig.EditorConfig).

## Recommended Make targets

| Target                  | When to run                                                |
|-------------------------|------------------------------------------------------------|
| `make all`              | Before every commit (fmt + vet + build + test)             |
| `make test-doctrine`    | After any change under `internal/` or `test/doctrine/`     |
| `make verify-reproducible` | After build-affecting changes (rare)                    |
| `make bench-quick`      | Before opening a PR that touches a hot path                |
| `make license-headers`  | Before committing new source files                         |
| `make terminology`      | Before committing prose changes                            |
| `make vault-gate`       | Before pushing to remote — runs every CI sub-check         |

## Editor configs

### VS Code

Recommended extensions:

- `editorconfig.editorconfig`
- `golang.go`
- `redhat.vscode-yaml`
- `ms-azuretools.vscode-docker`

Workspace settings (`.vscode/settings.json`, opt-in per developer):

```json
{
  "go.lintTool": "golangci-lint",
  "go.formatTool": "gofmt",
  "go.testFlags": ["-count=1"],
  "go.vetOnSave": "package",
  "editor.formatOnSave": true,
  "editor.tabSize": 4
}
```

### JetBrains GoLand / IntelliJ

- File → Settings → Tools → File Watchers — add `gofmt` watcher
- Plugins → install `editorconfig` (usually bundled)
- Plugins → install `Go Linter` and configure with golangci-lint

### Vim / Neovim

- `editorconfig/editorconfig-vim` plugin
- `fatih/vim-go` plugin (or coc-go for nvim users)
- Add `let g:go_metalinter_command = "golangci-lint"` to vimrc

## Common workflows

### Onboarding (first day)

```bash
git clone https://github.com/vault-genome/vaultgenome-core
cd vaultgenome-core
make all                  # confirm the tree builds clean
pre-commit install        # opt-in commit-time checks
```

### Investigating a failing CI run

```bash
make vault-gate           # mirrors CI exactly
# OR isolate the failure:
make test-doctrine        # invariants
make test-race            # races
make verify-reproducible  # build determinism
make terminology          # deprecated-term check
```

### Submitting a PR

```bash
git checkout -b feat/123-short-description
# ... edit ...
make all                  # local sanity
git commit -m "feat: ..."  # pre-commit hooks run here
git push -u origin feat/123-short-description
```

### Updating a dependency

```bash
# 1. Bump in go.mod
go get -u github.com/some/dep@v1.2.3

# 2. Run go mod tidy and re-vendor
go mod tidy
go mod vendor

# 3. Add justification (mandatory for new direct deps)
edit docs/dependencies/<name>.md

# 4. Update allowlist
edit scripts/dep_allowlist.txt

# 5. Verify
make vault-gate

# 6. Commit
```

## Troubleshooting

### "pre-commit: command not found"

Install pre-commit first: `pip install pre-commit` or
`brew install pre-commit`.

### "go-fmt hook fails on Windows"

The pre-commit-golang hooks call `gofmt` directly. On Windows ensure
`gofmt.exe` is in PATH and that line endings are LF (not CRLF; the
`mixed-line-ending` hook fixes this automatically).

### "make verify-reproducible fails after git pull"

Some files (e.g., `bin/`, `dist/`) may have stale state. Clean and
retry:

```bash
make clean-bin
rm -rf dist/repro
make verify-reproducible
```

### "I can't reproduce a CI failure locally"

The most common causes:

1. CI uses a clean `go mod cache`; locally yours may have a stale
   entry. Try `go clean -modcache; go mod download`.
2. CI runs with `count=1` to disable test caching; locally `go test`
   without `-count=1` may use cached results. Always pass `-count=1`
   for definitive results.
3. CI runs `make verify-reproducible` against a clean tree; any
   stray file under `bin/` or `dist/` may shift the comparison. Run
   `make clean-bin` first.

### "I want to skip pre-commit hooks for one commit"

```bash
git commit --no-verify -m "..."
```

Use sparingly. CI will fail on the same checks; bypassing pre-commit
just delays the failure to push time.
