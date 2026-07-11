# Contributing to runtime-contract

Thank you for helping improve `runtime-contract`. The project currently provides an installable CLI
skeleton and analyzer library APIs, but CLI analysis integration is not implemented and there is no
release.

## Before contributing

- Read the current [scope marker](docs/SCOPE.md).
- Use a public issue for reproducible bugs or feature proposals.
- Do not use public issues for vulnerabilities; follow [SECURITY.md](SECURITY.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Keep all public repository content in English.

## Pull requests

Fork the repository, create a focused branch, and open a pull request against `main`. Explain the
problem, the proposed change, and how the change was verified. Do not include secrets, credentials,
real `.env` files, private infrastructure details, or private filesystem paths.

Use Python 3.11 or newer and `uv >=0.11.28,<0.12`. Install all locked development dependencies with:

```text
uv sync --locked --all-groups
```

When dependencies change, update and commit `uv.lock`, then verify it with `uv lock --check`.

Run the normal local gates before pushing:

```text
./scripts/quality-gates.sh
```

Run compatibility checks on Python 3.11 through 3.14 before requesting review:

```text
./scripts/quality-gates.sh --full
```

The default comparison base is the merge base of `HEAD` and `origin/main`. Use
`--base-ref <ref>` when a different explicit base is required. Product coverage must retain at
least 90% branch coverage globally, and executable product lines changed in `BASE..HEAD` must have
100% coverage. A pull request with no changed executable product lines still has to pass the global
threshold.

Every workflow run from an external fork requires manual maintainer approval. External contributors
cannot change `.github/workflows/**`, `.github/actions/**`, `scripts/ci/**`, or
`scripts/quality-gates.sh`. Protected build, development-tool, test, lint, typing, and coverage
sections in `pyproject.toml` are also owner-only. Product dependencies and the corresponding
`uv.lock` update remain open to contributors.

If CI fails, reproduce the named stage locally, fix the root cause, rerun the complete local gates,
and push a corrected commit. Do not skip or weaken a gate. For documentation-only changes, also
verify links and consistency with the approved scope.

## Licensing and DCO sign-off

Contributions are accepted under the project's [Apache License 2.0](LICENSE) on an inbound-equals-outbound basis. This project does not use a Contributor License Agreement.

Every commit in a pull request must certify the [Developer Certificate of Origin 1.1](DCO.md) with a `Signed-off-by` trailer. Create a signed-off commit with:

```text
git commit -s
```

The trailer must use your real name and an email address you are authorized to use:

```text
Signed-off-by: Your Name <your.email@example.com>
```

If a commit is missing the trailer, amend that commit locally and update the pull request branch without altering commits that belong to other contributors.

Each `Co-authored-by` trailer must have a matching `Signed-off-by` trailer using exactly the same
name and email address. Do not add a sign-off on behalf of another contributor.
