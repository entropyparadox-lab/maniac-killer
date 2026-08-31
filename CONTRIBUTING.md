# Contributing to maniac-killer ⚡

Thank you for contributing to `maniac-killer`!

---

## 1. Branch Strategy & PR Workflow

We follow **GitHub Flow** with protected main branch:

* **`main` (Protected)**: Production release branch. Direct push to `main` is prohibited; changes land only via reviewed Pull Requests.
* **`feat/<name>` / `fix/<name>`**: Feature and bugfix branches.
* **`docs/<name>` / `perf/<name>`**: Documentation and performance optimizations.

---

## 2. Quality & Verification Gate

Before submitting a Pull Request:
1. **Code Formatting**: Must pass `cargo fmt --check`.
2. **Clippy Linting**: Must pass `cargo clippy -- -D warnings`.
3. **Test Suite**: Must pass `cargo test`.

---

## 3. Fast Local Git Hooks

Install the local pre-commit and pre-push validation hooks:
```bash
./scripts/setup-hooks.sh
```

---

## 4. Release & SemVer Policy

* **Semantic Versioning (SemVer 2.0.0)**:
  * `PATCH`: Bug fixes, security hardening, process watchdog edge cases.
  * `MINOR`: New monitoring endpoints, CLI flags, backwards-compatible additions.
  * `MAJOR`: Breaking configuration or CLI command changes.
* **Tag Immutability**:
  * Never delete or rewrite a published tag (`vX.Y.Z`).

---

## 5. Commit Message Format

We strictly enforce **Conventional Commits**:
```
<type>(<scope>): <subject>

Examples:
  feat(watchdog): add CPU threshold kill handler
  fix(macos): handle zombie processes in pstree
  docs: add daemon installation instructions
```
