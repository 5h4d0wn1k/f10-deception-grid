# F10 — Deception Grid (decoy orchestration planner)

A deterministic, offline, standard-library-only **defensive deception
planner**: given a network model of your own infrastructure, it assigns
**fake services**, **honeytokens**, and **decoy paths**, tracks engagement
events against those decoys, and scores **attacker dwell** per source so your
SOC can turn a single touch into an early-warning signal.

All assets are synthetic placeholders (`192.0.2.x`, `*.example.com`, fake
credentials). The planner performs no access, no traffic, and no collection —
it plans and scores engagements from data you feed it.

## Overview

- **Decoy planner** — turns a network model JSON (`fixtures/network-model.json`)
  into a deterministic decoy plan: 5 fake services, 4 honeytokens, and 6 decoy
  paths bound to TEST-NET hosts, with stable string ids and host-coverage stats.
- **Engagement tracker** — records events keyed to decoys: `primary_touch`,
  `credential_use`, `lateral_move`, `command_exec`, `persistence`,
  `exfil_stage`; rejects unknown stages and unknown decoy ids; emits a
  time-sorted timeline.
- **Attacker-dwell scoring** — per source IP, a 0-100 heuristic score from
  dwell time, stage depth, and decoy-kind breadth, with severity
  `INFO/LOW/MEDIUM/HIGH/CRITICAL` and a gate verdict (`MONITOR`/`ACTION`).
- **Fixtures** — the bundled network model plus a synthetic engagement
  scenario that exercises every engine path.
- **Reporting** — JSON or Markdown to `reports/` (gitignored).
- **Clean exit codes** — `0` success, `1` gate `ACTION` under `--strict`,
  `2` config/model/event error. `--demo` always exits `0`.

## CLI

```bash
python3 firmware/deception_grid.py --help
python3 firmware/deception_grid.py --demo                    # offline, exit 0
python3 firmware/deception_grid.py --model model.json --events events.json \
    --report reports/eng.json
python3 firmware/deception_grid.py --events events.json --report reports/r.md \
    --strict    # exit 1 when any attacker score >= gate_threshold
```

Config lives in `config.json` (`model`, `gate_threshold`, `report`).
`--report FILE.json` selects JSON output; any other extension yields Markdown.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## IMPORTANT: Read before use.

This tool plans **defensive deception on infrastructure you own**. Decoys,
honeytokens, and fake services are legitimate defensive controls when deployed
on your own systems or under explicit written authorization. Pointing them at —
or collecting engagement from — systems/networks you do not control is outside
this tool's license and is likely illegal.

### Authorization Requirements

You must own the systems modeled in the network JSON, or hold explicit written
authorization from the system owner to deploy decoys and monitor engagements
against them. Any real engagement logs you feed in must be lawfully obtained.

### Legal Framework

Unauthorized access to or interference with computer systems is governed by the
**Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive
on Attacks Against Information Systems** (2013/40/EU), and equivalent
legislation in other jurisdictions. Penalties include imprisonment and
significant fines. Deploying traps/tarpits on systems you do not own can
additionally implicate fraud, wiretap, and data-protection statutes (e.g.,
GDPR where decoy content is entangled with personal data).

### Acceptable Use

- Deploying fake services / honeytokens / decoy paths on your own hosts or
  authorized lab infrastructure
- Correlating engagement events with your SOC's incident-response workflow
- Authorized purple-/blue-team exercises within a written scope
- Academic research and education on deception and dwell-time detection

### Prohibited Use

- Planning or deploying decoys on systems you do not own or lack authorization
  for
- Entrapping, harvesting, or misleading individuals/entities without a lawful
  basis
- Collecting or processing personal data through decoys without GDPR or
  equivalent compliance
- Using deception to hide your own unauthorized activity
- Any use that violates applicable law, NDA, or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors
assume no liability for damages arising from use or misuse of this tool,
including incorrect dwell conclusions drawn from self-supplied engagement data.

### Responsible Disclosure

If the planner surfaces evidence of abuse against your own infrastructure
(unexpected engagements with your decoys), preserve logs and handle it through
your organization's incident-response process; where a third-party platform is
implicated, report to that platform's abuse team rather than publicly.

## Live Lab Test Plan

1. **Help** — `python3 firmware/deception_grid.py --help` prints argparse help,
   exits `0`.
2. **Demo** — `--demo` plans 15 decoys from the bundled model, replays the
   synthetic engagement scenario, writes `reports/demo.md`, exits `0`. Expected:
   attacker `203.0.113.11` scores `100 CRITICAL` (gate `ACTION`), `198.51.100.7`
   scores `20 LOW`.
3. **Determinism** — the planner produces identical decoy ids across runs
   (asserted by `test_deterministic_across_calls`).
4. **Tracker validation** — unknown stage/unknown decoy ids are rejected
   (exit `2` in file mode).
5. **Dwell heuristics** — long-dwell multi-stage engagement beats a single
   touch (asserted by `test_deep_progression_is_critical`).
6. **Strict gate** — `--events <scenario> --strict` exits `1` when any score
   ≥ `gate_threshold`.
7. **JSON report** — `--report out.json` yields parseable JSON with plan,
   timeline, and per-attacker scores.

## Metrics

| Metric | Definition |
|--------|-----------|
| Decoys planned | fake services + honeytokens + decoy paths assigned from the model |
| Decoy id | deterministic stable string id (`svc-*`, `tok-*`, `path-*`) |
| Host coverage | hosts carrying at least one decoy / total modeled hosts |
| Engagement event | `(src, decoy_id, event_type, ts)` in the stage vocabulary |
| Stage depth | distinct events progressed through the engagement stage chain |
| Dwell | seconds between first and last event for one source |
| Attacker score | 0-100 = dwell + depth + breadth + exfil bonus (deterministic) |
| Severity | INFO < LOW (>=20) < MEDIUM (>=40) < HIGH (>=60) < CRITICAL (>=80) |
| Gate | MONITOR / ACTION against `gate_threshold` |
| Exit codes | 0 success, 1 gate ACTION under `--strict`, 2 input/config error |

Verified offline: `--demo` exits `0`; 15 decoys planned across 6/10 hosts;
engagement scenario yields one CRITICAL (100) and one LOW (20) attacker.

## License

MIT License