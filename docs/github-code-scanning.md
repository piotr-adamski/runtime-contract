# GitHub Code Scanning

The repository's [example workflow](../.github/workflows/code-scanning.yml) installs
`runtime-contract`, runs `check --format sarif`, retains the report for seven days, and uploads it
with GitHub's `upload-sarif` action. Copy the workflow and its small
[configuration file](../.github/runtime-contract-code-scanning.yaml), then adapt the configured
roots and classifications to the target repository.

The workflow needs only the built-in `GITHUB_TOKEN`. Its top-level permissions are limited to
`contents: read` and `security-events: write`; no repository or third-party secret is required.
All third-party actions are pinned to commit SHAs.

The example runs for pushes to `main` and by manual dispatch. It intentionally does not request
write-capable Code Scanning permissions on pull-request workflows, where forked contributions
receive a read-only token.

`runtime-contract check` exits `1` after writing a complete SARIF report when active error findings
exist. The scan step accepts `0` and `1`, so findings still reach Code Scanning. Exit `2` remains a
workflow failure because it means no reliable result was produced. The upload and short-lived audit
artifact run whenever the SARIF file exists.

SARIF locations are repository-relative. Consequently GitHub can attach alerts to the exact source
line instead of showing repository-level findings. In a consumer repository installed from PyPI,
the installation step can be reduced to:

```yaml
- name: Install runtime-contract
  run: python -m pip install runtime-contract
```

The source checkout is used here until the first immutable PyPI release.
