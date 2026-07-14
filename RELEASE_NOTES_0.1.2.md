# runtime-contract v0.1.2

This patch makes the root composite GitHub Action safe for five-minute adoption from a clean
consumer repository while preserving the product CLI as the only analyzer and argument parser.

## Changes

- Add the root composite Action, injection-safe process adapter, public inputs and outputs,
  three-platform compatibility CI, consumer E2E, SARIF guidance, and Marketplace checklist.
- Exclude `.github` from default discovery so `runtime-contract check .` does not interpret the
  consumer's workflow YAML as Kubernetes. An explicit configuration `include` can still opt in.
- Publish the package from an exact current `main` SHA through PyPI Trusted Publishing before
  creating immutable Action tags. No PyPI token is used.

## Release gates

- Merge through the rebase-only protected branch.
- Require all pull-request checks and exact-main workflows to pass.
- Publish `runtime-contract==0.1.2` from the verified exact-main SHA.
- Create the signed immutable `v0.1.2` tag only after the PyPI version exists.
- Promote `v0` only after public immutable-tag adoption succeeds.

The existing `v0.1.1` Action tag remains immutable and is not promoted because public adoption
found the `.github` discovery conflict. It does not identify a PyPI package release.
