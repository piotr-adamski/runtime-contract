# runtime-contract

Static, local CLI for finding inconsistencies between environment variables used in application code and how they are documented and supplied at build and runtime.

> **Status:** Scope approved; implementation pending.

An independent open-source project maintained by Piotr Adamski.

The planned v0.1.0 inputs are:

- Python;
- JavaScript and TypeScript;
- `.env.example`;
- Dockerfile;
- Docker Compose;
- standard Kubernetes manifests.

The planned read-only commands are `scan`, `check`, `explain`, and `diff`.

Local-only operation without telemetry or data transmission is a planned project requirement. It is not an implemented feature yet. There is currently no working package, installation path, or release.

## Project information

- Maintainer: Piotr Adamski
- License: [Apache-2.0](LICENSE)
- Changes: [CHANGELOG.md](CHANGELOG.md)
- Contributing: [CONTRIBUTING.md](CONTRIBUTING.md)
- Code of Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)
- Security: [SECURITY.md](SECURITY.md)
