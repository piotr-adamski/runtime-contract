# Public-repository pilot protocol v1

This is the bounded ten-repository pilot, not the final 75-repository study. Freeze the corpus
in a commit before scanning. The product baseline is public `runtime-contract==0.1.2`; never
install dependencies or execute code from a subject repository. Acquisition and installation
are excluded from timing. One warm-up precedes three measured runs. Use Linux, GNU time,
30 CPU seconds, 45 wall seconds and 1 GiB address space per scan. Report median wall time and
maximum RSS, CPU count, OS, Python and CLI version. Preserve failed/partial outcomes in denominators.

Select from fifteen candidates before observing scanner output. Each included repository must
have a named open-source license, a commit within twelve months, supported consumers and provider
declarations, and fit acquisition budgets. Include Python, JS/TS, mixed projects, Compose and
Kubernetes. A pilot need not meet the final study's 25/25/25 language quotas. Record exclusions.

Acquire only immutable full SHA archives from public GitHub without credentials, hooks or
submodules. Reject escaping paths, archive identity mismatch and resource excess. Do not extract
real `.env*` files, private-key containers, symlinks or generated dependency/build directories;
record these exclusions and the acquired tree digest. Never copy node_modules, .next or .open-next.
Large-file exclusions are reported and limit coverage; they are not evidence of complete repository
coverage. Recheck source/config digests before and after scanning.

Run each repository twice: out-of-the-box with no added configuration, and configured with
reviewed component roots and source declarations. Configuration must not add suppressions,
classifications or severity overrides to improve results. Freeze both corpus and configurations
before the first scan. Record each exact configuration digest.

Each finding receives one of: `confirmed_error`, `probable_error`, `false_positive`,
`unsupported_pattern`, `intentional_configuration`, `cannot_determine`. Include an explanation,
confidence, repository SHA, finding ID, rule, component, environment, phase, reviewer/date and
source references. A conservative unresolved verdict is not a false positive. Precision is
confirmed_error / (confirmed_error + false_positive), undefined when its denominator is zero.
Do not count probable errors as confirmed. Public code cannot prove live delivery.

AI-assisted technical annotations and a second technical review are identified explicitly. They
are not independent human ground truth. Ambiguous judgments remain cannot_determine pending a
maintainer decision; report the number awaiting human adjudication. Do not publish validated
precision or population recall claims without the corresponding ground truth.

RTC002/RTC003 require private security triage. Withhold their source/key identifiers and entire
affected raw reports from the public export. Publish aggregate counts and opaque IDs only.
Do not contact maintainers or submit issues automatically. All public reports pass the exporter
allowlist; never upload acquired repositories or uncontrolled stderr.

Controlled mutations include missing delivery, wrong build/runtime phase, unsafe sensitive
literal, Pydantic alias, dynamic name, unresolved envFrom, cross-component delivery and conflicting
providers. Record patch, expected finding/completeness and observed outcome for every case.
Fixture-derived mutation detection is not population recall. Original subjects remain unchanged.

Every finding must have an annotation. A second review covers all error findings and at least
20% of warning/info. Report pending human review separately. More than 300 findings, unresolved
technical/process failures or absent ground truth require HOLD before expanding to 75. A finished
pilot may legitimately end HOLD. Release a reproducible pilot report, data checksums, methodology,
limitations and a ranked quality backlog. The final 75-repository report remains future scope.
