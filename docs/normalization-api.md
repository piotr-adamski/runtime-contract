# Fact normalization API

`runtime_contract.normalization` converts analyzer `FactObservation` objects into a canonical,
facts-only `Contract`:

```python
from runtime_contract.normalization import normalize_observations

contract = normalize_observations(observations)
```

The function accepts any iterable and consumes it once. Input order and observation confidence do
not affect the result. It normalizes relative POSIX source paths to Unicode NFC, removes safe `.`
and `..` segments without filesystem access, reconstructs domain facts through their public models,
recomputes location-dependent IDs, deduplicates byte-equivalent facts, and returns domain-sorted
collections.

Normalization is static and pure. It does not read files, resolve symlinks, import or execute the
analyzed project, generate findings, retain analyzer diagnostics, or include configuration values or
source snippets in the result.

## Errors

`NormalizationError` is a technical error with a stable `NormalizationErrorCode`, a redacted
message, and optional `fact_id` and `fact_kind` context. Supported codes are:

- `CONFLICTING_FACT`: the same canonical fact ID has different canonical content;
- `INVALID_LOCATION`: a source location is unsafe or violates the domain range contract;
- `INVALID_FACT_REFERENCE`: a Consumer or Provider reference is missing or crosses components;
- `UNSUPPORTED_FACT`: the observation kind and concrete fact model do not match or the model is not
  supported.

These errors are not rule findings and do not belong to the RTC001–RTC012 catalog. Callers should
map them to a technical failure rather than choosing a fact by analyzer order or confidence.
