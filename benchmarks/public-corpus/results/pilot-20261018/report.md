# Public-repository pilot — 0.1.2

Decision: **HOLD before expanding to 75 repositories**.

The ten-repository pilot is complete as a technical experiment. Annotations are AI-assisted
technical assessments, not independent human ground truth. This report makes no validated
precision, population recall, security-vulnerability or production-outage claim.

Runs: 20; findings: 1982; statuses: `{'failed': 18, 'complete': 1, 'partial': 1}`.
Raw reports withheld for security triage: 10; human adjudications pending: 1982.
Second technical review covered 1894 findings; this is AI review, not human ground truth.

| Repository | Mode | Status | Findings | Median seconds | Peak RSS KiB |
|---|---|---|---:|---:|---:|
| fastapi/full-stack-fastapi-template | out-of-the-box | failed | 60 | 0.813 | 46420 |
| fastapi/full-stack-fastapi-template | configured | failed | 8 | 0.779 | 46476 |
| umami-software/umami | out-of-the-box | failed | 158 | 14.164 | 77252 |
| umami-software/umami | configured | failed | 146 | 14.365 | 77136 |
| louislam/dockge | out-of-the-box | failed | 100 | 2.086 | 58432 |
| louislam/dockge | configured | failed | 39 | 2.081 | 58340 |
| louislam/uptime-kuma | out-of-the-box | failed | 199 | 12.992 | 75048 |
| louislam/uptime-kuma | configured | failed | 47 | 12.607 | 74204 |
| GoogleCloudPlatform/microservices-demo | out-of-the-box | failed | 217 | 1.834 | 52896 |
| GoogleCloudPlatform/microservices-demo | configured | complete | 63 | 0.964 | 49056 |
| docmost/docmost | out-of-the-box | failed | 60 | 6.906 | 54744 |
| docmost/docmost | configured | failed | 25 | 6.943 | 54640 |
| healthchecks/healthchecks | out-of-the-box | failed | 67 | 10.318 | 136344 |
| healthchecks/healthchecks | configured | partial | 34 | 1.258 | 48604 |
| paperless-ngx/paperless-ngx | out-of-the-box | failed | 464 | 4.626 | 62696 |
| paperless-ngx/paperless-ngx | configured | failed | 66 | 3.046 | 60952 |
| django-helpdesk/django-helpdesk | out-of-the-box | failed | 14 | 1.267 | 50612 |
| django-helpdesk/django-helpdesk | configured | failed | 11 | 1.152 | 50676 |
| wagtail/bakerydemo | out-of-the-box | failed | 102 | 2.498 | 64728 |
| wagtail/bakerydemo | configured | failed | 102 | 2.500 | 64780 |

## Aggregate reproduction

`measurements.json`, `annotations.json` and `diagnostics.json` are the aggregate inputs.
Every finding has exactly one annotation. RTC002/RTC003 rows use opaque IDs and omit
source/key metadata; affected raw reports remain private. Uncontrolled stderr is withheld.

| Verdict | Count |
|---|---:|
| cannot_determine | 1758 |
| false_positive | 212 |
| unsupported_pattern | 12 |

## Controlled mutations

Exact expected rule and completeness matched: **6/8**.
All controls exclude the expected rule. These are synthetic witnesses, not population recall.
See [patches, provenance and results](../../mutations/README.md).

| Witness | Expected | Observed after | Match |
|---|---|---|---|
| missing-delivery | RTC001 / complete | RTC001 / complete | True |
| wrong-phase | RTC010 / complete | RTC001 / complete | False |
| sensitive-literal | RTC002 / complete | RTC002 / complete | True |
| pydantic-alias | RTC001 / complete | RTC001, RTC005 / complete | True |
| dynamic-name | RTC006 / partial | RTC006 / partial | True |
| unresolved-envfrom | RTC009 / complete | none / complete | False |
| cross-component-delivery | RTC001 / complete | RTC001, RTC005 / complete | True |
| conflicting-default | RTC007 / complete | RTC007 / complete | True |

## Performance

- out-of-the-box: p50 3.562s; nearest-rank p95 14.164s; includes partial/failed scans.
- configured: p50 2.290s; nearest-rank p95 14.365s; includes partial/failed scans.

## Quality backlog and resumption conditions

1. Diagnose generic JSON/YAML discovery as Kubernetes, preserving explicit opt-in behavior.
2. Diagnose modern Python syntax under the recorded Python 3.11 parser and supported Dockerfile aliases.
3. Improve component/target mapping and explain missing delivery without implying a runtime outage.
4. Add static wrapper/alias handling only after ranking the observed dynamic diagnostics.
5. Finish private security triage and independent human adjudication before precision claims.

Ranking is by reliability impact first; diagnostic frequencies are in `diagnostics.json`.
HOLD is required because unsupported parsing and unresolved judgments remain; scale only after
a bounded parser/mapping correction, an identical-SHA rerun and a feasible human-review plan.

## Limitations

The pilot is intentionally small and not statistically representative. Configured scopes omit
tests/examples only where declared in committed configuration; compare scope as well as counts.
Acquisition omits real dotenv/private-key/generated files, symlinks and oversized files; receipts
record those exclusions. Complete scan status covers acquired selected inputs only. RSS and time
depend on host contention; this run is observational, not a dedicated-host performance claim.
Controlled fixture mutations measure the selected cases, not population recall. The 75-repository
study and its final publication remain future work.
