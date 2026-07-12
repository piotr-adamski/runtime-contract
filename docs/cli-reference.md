# CLI reference

This is the canonical option reference for the installed `runtime-contract` v0.1 CLI. Command
`--help` is generated from the same declarations and provides short examples; this document owns
the stable meaning, defaults, accepted values, and output behavior.

## Global

| Option | Meaning |
|---|---|
| `--version` | Print the installed distribution version and exit `0`. Missing package metadata exits `2`. |
| `--install-completion` | Install shell completion using Typer's supported shell integration. |
| `--show-completion` | Print completion source without installing it. |
| `--help` | Print help and exit `0`. |

With no command, the CLI prints help. A misspelled command or option exits `2`, writes usage and a
suggestion to stderr, and never emits a report.

## `scan [PATH]`

`PATH` defaults to `.`. The command performs static analysis and emits a report; findings never
produce exit `1` for `scan`.

| Option | Accepted/default | Meaning |
|---|---|---|
| `--config PATH` | `runtime-contract.yaml` | Config path relative to `PATH`; it must remain inside the project root. |
| `--root NAME` | repeatable; all configured roots | Restrict analysis to named roots. |
| `--environment NAME` | none | Select one configured environment profile. |
| `--include GLOB` | repeatable | Replace global include globs; hard safety exclusions still apply. |
| `--exclude GLOB` | repeatable | Replace global exclude globs. |
| `--format FORMAT` | `text`; `text/json/sarif` | Override environment/YAML output format. |
| `--output PATH` | stdout | Atomically write the report instead of stdout. |
| `--fail-on LEVEL` | `error`; `error/warning/info/never` | Resolve policy metadata; `scan` remains non-blocking for findings. |
| `--quiet`, `-q` | false | Text only: print the final status. Mutually exclusive with verbosity. |
| `--verbose`, `-v` | `0`; at most `-vv` | Text only: increase detail. |
| `--color MODE` | `auto`; `auto/always/never` | ANSI policy for text. `auto` requires a TTY and respects `NO_COLOR`. |
| `--no-emoji` | false | Disable TTY symbols. |
| `--width N` | terminal width; `40..240` | Deterministic text wrapping width. |

`--output` and configured report output are mutually exclusive. JSON and SARIF bytes are unaffected
by text presentation options.

## `check [PATH]`

`PATH` defaults to `.`. `check` runs the same scanner and active policy as `scan`, then returns `1`
only for a complete result containing at least one active finding at or above `--fail-on`.

| Option | Accepted/default | Meaning |
|---|---|---|
| `--config PATH` | `runtime-contract.yaml` | Same safe config resolution as `scan`. |
| `--environment NAME` | none | Select a configured profile. |
| `--format FORMAT` | `text`; `text/json/sarif` | Override environment/YAML format. |
| `--output PATH` | stdout | Atomic output path. |
| `--fail-on LEVEL` | `error`; `error/warning/info/never` | Failure threshold after suppressions and severity overrides. |
| `--report PATH` | none | Relative report path override from execution configuration. Mutually exclusive with `--output`. |
| `--color MODE` | `auto`; `auto/always/never` | Text ANSI policy. |
| `--no-emoji` | false | Disable TTY symbols. |
| `--width N` | terminal width; `40..240` | Text wrapping width. |

## `explain RULE_OR_FINDING_ID [PATH]`

Without `PATH`, a catalog rule such as `RTC001` is explained. A finding ID requires either a
canonical JSON report or project directory. Analysis is offline and read-only.

| Option | Accepted/default | Meaning |
|---|---|---|
| `--format FORMAT` | `text`; `text/json` | Explanation format. SARIF is rejected with exit `2`. |
| `--output PATH` | stdout | Atomic output path. |

## `diff LEFT RIGHT`

Both inputs must be directories or both canonical JSON reports. The command compares semantic
contracts without invoking Git and exits `0` for both identical and different valid inputs.

| Option | Accepted/default | Meaning |
|---|---|---|
| `--environment NAME` | none | Shared profile for directory scans; saved reports must match it. |
| `--format FORMAT` | `text`; `text/json` | Diff format. SARIF is rejected with exit `2`. |
| `--output PATH` | stdout | Atomic output path. |

## Configuration commands

`config validate [PATH]` requires `runtime-contract.yaml`, validates filesystem references, and
accepts `--format text|json`. `config explain VARIABLE` explains ordered classification selection
and accepts `--path PATH` (default `.`), `--root NAME`, and `--environment NAME`.

## Exit and stream contract

| Exit | Contract |
|---:|---|
| `0` | Successful command; for `check`, no active finding reaches the threshold. |
| `1` | Complete `check` with an active finding reaching the threshold. No other command uses `1`. |
| `2` | Usage/configuration/technical error or partial/failed analysis. |
| `130` | Process interrupted by the user. |

Reports use stdout or only the selected output file. Usage and technical errors use stderr.

Execution precedence is built-in defaults, YAML, the four documented `RUNTIME_CONTRACT_*`
variables, then explicit CLI options. See [configuration reference](runtime-contract-yaml.md).
