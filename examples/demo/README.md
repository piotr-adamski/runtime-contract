# Offline broken/fixed demo

This domain-neutral full-stack example is a reproducible bug-report fixture. It uses only
synthetic placeholder names and values and does not need network access, containers, or secrets.

```console
runtime-contract check examples/demo/broken
runtime-contract check examples/demo/fixed
python scripts/generate_demo_outputs.py --check
```

`broken/` intentionally delivers sensitive configuration through plain Compose values and a
Kubernetes ConfigMap. `fixed/` replaces those paths with variable and Secret references. Both
projects contain Python and JavaScript consumers, `.env.example`, Dockerfile, Compose, Kubernetes,
and `runtime-contract.yaml` inputs.

Committed output under `outputs/` records terminal, canonical JSON, and SARIF for both states.
When reporting a bug, include the tool version, command, one of these minimized projects, and the
matching output format. Never include real credentials or proprietary source.
