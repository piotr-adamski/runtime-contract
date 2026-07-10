# Contributing to runtime-contract

Thank you for helping improve `runtime-contract`. The project currently provides an installable CLI
skeleton, but analysis is not implemented and there is no release.

## Before contributing

- Read the current [scope marker](docs/SCOPE.md).
- Use a public issue for reproducible bugs or feature proposals.
- Do not use public issues for vulnerabilities; follow [SECURITY.md](SECURITY.md).
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- Keep all public repository content in English.

## Pull requests

Keep each pull request focused. Explain the problem, the proposed change, and how the change was verified. Do not include secrets, credentials, real `.env` files, private infrastructure details, or private filesystem paths.

Use Python 3.11 and run the repository's validation commands before opening a pull request:

```text
uv sync --dev
uv run ruff format --check .
uv run ruff check .
uv run mypy --strict src tests
uv run pytest
uv build
```

For documentation-only changes, also verify links and consistency with the approved scope.

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
