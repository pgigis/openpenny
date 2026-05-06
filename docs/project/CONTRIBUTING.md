# Contributing to OpenPenny

Contributions are welcome. If you are unsure about anything, open an issue or submit a pull request anyway — a short list of guidelines should not stop a good change from landing.

The rest of this page outlines the practices that help us review and merge changes efficiently.

---

## Overview

[OpenPenny](https://github.com/pgigis/openpenny) is a mono-repository consisting of four main components:

1. **Active Mode**
2. **Passive Mode**
3. **Build System**
4. **Testing Suite**

All components share a single version number, defined by the repository’s git tags.

---

## Issues

### Reporting an Issue

When reporting a bug or unexpected behaviour, please:

- Ensure you are testing against the latest released version.
- Provide clear, reproducible steps and any necessary data.
- Include relevant OpenPenny logs.
- Add appropriate labels when applicable.

---

## Contribution Guidelines

- Ensure an issue exists for the work you intend to do and comment when you begin to avoid duplication.
- Use the PR template (`.github/pull_request_template.md`) and keep scope focused.
- Include build/test notes in the PR (e.g., `cmake -S . -B build && cmake --build build`, `ctest --test-dir build`).
- Follow existing code style; run `clang-format` for C++ where applicable.
- Update docs when flags/config/behaviour change.
- For security issues, do not open a public issue; email as described in `SECURITY.md`.

---
