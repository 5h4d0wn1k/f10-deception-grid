> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# F10 — Deception Grid

Defensive deception planner for early attacker detection — assigns fake services, honeytokens, and
decoy paths from a network model, tracks engagement events, and scores per-source attacker dwell so
a SOC turns one touch into an early-warning signal. Offline and standard-library only.

![MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub stars](https://img.shields.io/github/stars/5h4d0wn1k/f10-deception-grid)
![GitHub last commit](https://img.shields.io/github/last-commit/5h4d0wn1k/f10-deception-grid)
![GitHub issues](https://img.shields.io/github/issues/5h4d0wn1k/f10-deception-grid)

## Why

Modern detections miss what they never see, so defenders bait: a decoy service, a honeytoken, a
fake path only an attacker would touch. F10 turns your own network model (RFC 5737 hosts,
`*.example.com`, fake credentials) into a deterministic deception plan, then scores engagement
events by dwell time, stage depth, and decoy breadth into a 0-100 attacker score with a
`MONITOR`/`ACTION` gate. It is a blue-team and purple-team educational instrument for deception and
dwell-time detection — and it is purely a planner: it performs no access, no traffic, and no
collection. Only model infrastructure you own or hold written authorization for.

## Features

- **Decoy planner** — 5 fake services, 4 honeytokens, 6 decoy paths from a network-model JSON,
  with stable ids (`svc-*`, `tok-*`, `path-*`) and host-coverage stats.
- **Engagement tracker** — stage vocabulary (`primary_touch`, `credential_use`, `lateral_move`,
  `command_exec`, `persistence`, `exfil_stage`), unknown-stage rejection, time-sorted timeline.
- **Dwell scoring** — deterministic 0-100 heuristic per source with
  `INFO/LOW/MEDIUM/HIGH/CRITICAL` severity and a gate verdict.
- **Reports** — JSON or Markdown to `reports/` (gitignored).
- **Clean exit codes** — `0` success, `1` gated `ACTION` under `--strict`, `2` input/config error.

## Quickstart

Prerequisite: Python 3 (standard library only).

```bash
python3 firmware/deception_grid.py --help
python3 firmware/deception_grid.py --demo                       # offline, exit 0
python3 firmware/deception_grid.py --model model.json --events events.json --report reports/eng.json
python3 firmware/deception_grid.py --events events.json --report reports/r.md --strict
```

Config defaults live in `config.json` (`model`, `gate_threshold`, `report`); a synthetic engagement
scenario is bundled to exercise every engine path.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Project structure

- `firmware/deception_grid.py` — planner, tracker, scoring, and CLI.
- `config.json` — planner defaults.
- `fixtures/` — `network-model.json` plus the scenario fixture.
- `tests/` — determinism, validation, and scoring tests.

## Documentation

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [SECURITY.md](SECURITY.md)
- [ETHICS.md](ETHICS.md) · [SCOPE.md](SCOPE.md)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Keep the planner deterministic and defensive-only.

## License

MIT — see [LICENSE](LICENSE).