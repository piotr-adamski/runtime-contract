# Security Policy

## Supported versions

The latest v0.1.x release receives security fixes. Reports affecting the current `main` branch are
also accepted, but `main` is a development target and not a stable release. Older v0.1.x patch
releases are unsupported after a newer patch release becomes available unless this policy states
otherwise.

| Version | Support status |
| --- | --- |
| Latest v0.1.x release | Supported |
| Older v0.1.x releases | Unsupported after a newer patch release is available |
| `main` | Reports accepted; not a supported release |

## Reporting a vulnerability

Do not report vulnerabilities through public GitHub issues, pull requests, discussions, or other public channels.

Use [GitHub Private Vulnerability Reporting](https://github.com/piotr-adamski/runtime-contract/security/advisories/new) as the primary reporting channel. If that channel is unavailable, email [piotr.adamski@brillnet-app.com](mailto:piotr.adamski@brillnet-app.com) with the subject prefix `[runtime-contract security]`.

Include the affected commit or version, impact, reproduction steps, and any suggested mitigation. Do not include secrets or third-party personal data.

The maintainer aims to:

- acknowledge a report within 3 business days;
- provide an initial assessment within 7 calendar days;
- coordinate disclosure and remediation based on severity and affected users.

These are response targets, not a fixed remediation service-level agreement. Please allow a reasonable period for investigation and coordinated disclosure before publishing details.

The product threat model, local data boundaries, parser controls, no-telemetry contract, and
residual limitations are maintained in [docs/security-and-privacy.md](docs/security-and-privacy.md).
