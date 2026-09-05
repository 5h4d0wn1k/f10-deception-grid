# F10 — Deception Grid v2

A pure-Python deception toolkit (defensive) that generates and deploys canary tokens, simulates a fake internal git server, and detects + serves web tarpits against AI-crawlers, correlating everything into a deception timeline with tarpit-bite statistics.

## Overview

- **Canary generator + deployer** — fabricates fake credentials, configs, CI logs, and endpoints, each embedded with an unprompted tripwire hash
- **Fake internal git server (SIMULATION)** — a mock repo whose "cloned" content is laced with canary tokens; any clone/fetch fires a canary event
- **Web tarpit detector** — parses a request log and flags likely bot/scraper/AI-crawler patterns (GPTBot, ClaudeBot, python-requests, curl, headless-browser, `.env`/`/admin` probing)
- **Prompt-injection decoy pages** — generator emits benign decoy HTML enantiomers that look like internal SSO/admin docs to entangle and fingerprint crawlers
- **Correlation + bite stats** — all canary, git-clone, and tarpit events merge into a timestamped timeline with per-type counts and tarpit-bite statistics (unique IPs, top targets)
- Runs entirely offline on an embedded sample log — zero third-party dependencies

## Features

- **`CanaryDeployer`** — one-call deployment plans (`deploy(["web_creds", "db_config", "ci_log", "cd_endpoint"])`)
- **`FakeGitServer`** — simulated repo clone/fetch returning token-laced content and recording a canary event per requester
- **`TarpitDetector`** — NCSA-log parsing, 3 UA-pattern classes, suspicious-path probing, per-UA hit stats and flagging rate
- **`generate_tarpit_page`** — 600-ish char prompt-injection decoy HTML that looks like "internal SSO docs" to a crawler
- **`correlate_events` / `tarpit_bite_stats`** — unified timeline, event-type histogram, unique bitten IPs, top targeted paths
- **Offline self-test** — 5 deployed tokens, 1 git-clone canary fire, 4/6 flagged log requests, 10 correlated events, exits `0`

## Installation

No external dependencies required — uses Python standard library only.

```bash
git clone <repo> && cd f10-deception-grid
python3 firmware/deception_grid.py
```

## Usage

```python
from firmware.deception_grid import (
    CanaryDeployer, FakeGitServer, TarpitDetector,
    generate_tarpit_page, correlate_events, tarpit_bite_stats,
)

deployer = CanaryDeployer()
tokens = deployer.deploy(["web_creds", "ci_log"])
git_srv = FakeGitServer(tokens)
git_srv.clone(requester="203.0.113.44")

detector = TarpitDetector()
flagged = detector.analyze_log(SAMPLE_REQUEST_LOG)
print(detector.stats())
```

The offline demo runs the whole grid head-to-toe (deploy → clone → detect → serve decoy → correlate → stats) and exits `0`:

```python
python3 firmware/deception_grid.py
```

## Example Output

```
[3] Web Tarpit Detector (AI-crawler flagging)
    Parsed 6 requests, flagged 4 as suspicious:
      - 198.51.100.9     /docs              UA='Mozilla/5.0 (compatible; GPTBot/1.2' matches=['known-ai-crawler-UA']
      - 203.0.113.44     /admin             UA='python-requests/2.31.0' matches=['generic-http-client', 'no-browser-fingerprint']

[5] Correlated Deception Timeline & Bite Stats
    Total correlated events: 10
      canary_deployed      -> 5
      fake_git_clone       -> 1
      tarpit_bite          -> 4
    Tarpit-bite statistics:
      total bites       : 4
      unique IPs bitten : 3
```

## IMPORTANT: Read before use.

This toolkit implements **defensive deception on infrastructure you own**. Canaries, decoys, and tarpits are legal and valuable when deployed on your own network or with explicit written authorization — and they are **fraud, a CFAA violation, and/or unauthorized "trap" activity** when aimed at third parties. Serving fake content to a crawler operated by someone else may constitute unauthorized interference with their systems and can violate their terms of service, so keep every deployment scoped to assets you control.

### Authorization Requirements

You must own the systems on which you deploy canaries and tarpits, or hold explicit written authorization from the system owner. Monitoring "clones" of repositories that are not yours, or serving decoys to traffic you have no right to observe, is outside this tool's license and likely illegal.

### Legal Framework

Unauthorized access to or manipulation of computer systems is governed by the **Computer Fraud and Abuse Act (CFAA)** (18 U.S.C. § 1030), the **EU Directive on Attacks Against Information Systems** (2013/40/EU), and equivalent legislation in other jurisdictions. Penalties include imprisonment and significant fines. Deploying honeypots/tarpits on systems you do not own can additionally implicate fraud, wiretap, and data-protection statutes (e.g., GDPR when decoys contain personal data).

### Acceptable Use

- Deploying canaries in your own repos, CI pipelines, and configs to detect exfiltration
- Running the fake git server or tarpit detector against your own endpoints and request logs
- Authorized purple-team/red-team exercises within a written scope
- Academic research on deception, honeypots, and AI-crawl detection in lab environments

### Prohibited Use

- Deploying canaries or tarpits on or against systems you do not own or lack authorization for
- Entrapping, harvesting, or materially misleading individuals or entities without a lawful basis
- Collecting or processing personal data through decoys without GDPR/equivalent compliance
- Using deception tooling to hide evidence of your own unauthorized activity
- Any use that violates applicable law or terms of service

### No Warranty

This software is provided "as is" without warranty of any kind. The authors assume no liability for damages arising from use or misuse of this tool, including legal consequences of deploying deception on infrastructure you do not control.

### Responsible Disclosure

If your canaries or detector surface abuse of your own infrastructure (e.g., a cloned fake repo, a probe of your tarpit endpoints), preserve logs, then report the incident through your organization's incident-response process — and, where a third-party platform is implicated, to that platform's abuse team rather than publicly.

## License

MIT License