"""
F10 — Deception Grid v2
Canary tokens + fake internal git server simulation + AI-crawler web tarpit,
with correlated deception-event timeline and tarpit-bite statistics.
DEFENSIVE deception tooling for use ONLY on your own infrastructure.
"""

import hashlib
import json
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# 1. Canary-token generator & deployer
# ---------------------------------------------------------------------------

class CanaryToken:
    __slots__ = ("token_id", "kind", "payload", "tripwire", "seeded_at")

    def __init__(self, kind: str, payload: str):
        self.token_id = uuid.uuid4().hex[:16]
        self.kind = kind
        self.payload = payload
        # Tripwire hash lets us detect a triggered token even if renamed
        self.tripwire = hashlib.sha256(payload.encode()).hexdigest()[:24]
        self.seeded_at = time.time()

    def to_dict(self) -> Dict:
        return {
            "token_id": self.token_id,
            "kind": self.kind,
            "payload": self.payload,
            "tripwire": self.tripwire,
            "seeded_at": self.seeded_at,
        }

    def __repr__(self):
        return f"CanaryToken({self.kind}, id={self.token_id[:6]}...)"


class CanaryDeployer:
    """Generates canary tokens and 'deploys' them into fake assets
    (fake creds, fake configs, fake CI logs)."""

    FABRICATED_CATEGORIES = [
        "fake_credential", "fake_config", "fake_ci_log", "fake_endpoint",
    ]

    def __init__(self):
        self.tokens: List[CanaryToken] = []

    def generate(self, kind: str, context: str = "") -> CanaryToken:
        if context:
            payload = f"{context}::canary-{kind}::{uuid.uuid4().hex}"
        else:
            payload = f"{kind}::{uuid.uuid4().hex}::SUPERVISED-CANARY"
        token = CanaryToken(kind, payload)
        self.tokens.append(token)
        return token

    def deploy_fake_creds(self, service: str) -> CanaryToken:
        return self.generate("fake_credential",
                             f"service={service},user=svc-canary,pass=" +
                             uuid.uuid4().hex[:12])

    def deploy_fake_config(self, path: str) -> CanaryToken:
        return self.generate("fake_config", f"path={path}")

    def deploy_fake_ci_log(self, job: str) -> CanaryToken:
        return self.generate("fake_ci_log", f"job={job}")

    def deploy_fake_endpoint(self, host: str) -> CanaryToken:
        return self.generate("fake_endpoint", f"host={host}")

    def deploy(self, plan: List[str]) -> List[CanaryToken]:
        """Deploy according to a plan of strings like 'web_creds',
        'db_config', 'ci_log', 'cd_endpoint'."""
        out = []
        for item in plan:
            if item == "web_creds":
                out.append(self.deploy_fake_creds("web-prod"))
            elif item == "db_config":
                out.append(self.deploy_fake_config("/etc/db/config.yaml"))
            elif item == "ci_log":
                out.append(self.deploy_fake_ci_log("ci-build-4711"))
            elif item == "cd_endpoint":
                out.append(self.deploy_fake_endpoint("deploy.corp.internal:8443"))
        return out


# ---------------------------------------------------------------------------
# 2. Fake internal git server simulation
# ---------------------------------------------------------------------------

class FakeGitServer:
    """A mock git server whose cloned/fetched content is laced with
    canary tokens.  'Cloning' this repo triggers canary events."""

    def __init__(self, canaries: List[CanaryToken]):
        self.canaries = canaries
        self.clone_log: List[Dict] = []

    def _laced_commit_content(self, extra: str = "") -> str:
        lines = ["# fake-internal-repo (simulated)",
                 "# this content is fabricated for deception"]
        for c in self.canaries:
            lines.append(f"# canary <{c.payload}>"
                         f" :: tripwire={c.tripwire}")
        if extra:
            lines.append(extra)
        return "\n".join(lines)

    def clone(self, requester: str) -> Dict:
        """Simulate someone cloning the fake repo.  Returns content with
        embedded canaries and records the event."""
        now = time.time()
        event = {
            "event_id": uuid.uuid4().hex[:12],
            "ts": now,
            "iso": datetime.fromtimestamp(now, tz=timezone.utc).isoformat(),
            "type": "canary_fired",
            "canary_count": len(self.canaries),
            "requester": requester,
            "surface": "fake_git_clone",
        }
        self.clone_log.append(event)
        return {"event": event, "content": self._laced_commit_content()}

    def fetch(self, requester: str) -> Dict:
        return self.clone(requester)


# ---------------------------------------------------------------------------
# 3. Web tarpit detector for AI-crawlers
# ---------------------------------------------------------------------------

# Patterns flagging likely bot/scraper/AI-crawler request behaviour.
BOT_PATTERNS = [
    (r"GPTBot|ChatGPT-User|OAI-SearchBot|PerplexityBot|ClaudeBot|"
     r"anthropic-ai|Bytespider|CCBot|Google-Extended|facebookexternalhit",
     "known-ai-crawler-UA"),
    (r"headless|selenium|phantomjs|playwright|puppeteer",
     "browser-automation-UA"),
    (r"requests|python-requests|httpx|aiohttp|urllib|Go-http-client|curl/",
     "generic-http-client"),
]

CANARY_DECOY_HTML = """<!DOCTYPE html>
<html><head><title>docs (internal)</title></head>
<body>
  <!-- SUPER-DECOY-CANARY {token} -->
  <meta name="robots" content="noindex">
  <h1>SSO &amp; Admin Documentation</h1>
  <p>Login redirect: https://sso.{{HOST}}/saml/metadata</p>
  <div class="creds-placeholder">{token}</div>
  <p>For internal ops only. DB at postgres://ops:{{dbpass}}@db.{{HOST}}:5432/ops</p>
</body></html>
"""


class TarpitDetector:
    """Parse a request log and flag likely-bot/scraper patterns."""

    def __init__(self):
        self.flagged: List[Dict] = []
        self.parsed: List[Dict] = []

    def parse_line(self, line: str) -> Optional[Dict]:
        """Parse a rudimentary NCSA-style log line."""
        # e.g. 1.2.3.4 - - [05/Sep/2026:10:00:00 +0000] "GET /path HTTP/1.1" 200 123 "ref" "UA"
        m = re.match(
            r'^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([^"]+)"\s+(\d+)\s+'
            r'(\d+)\s+"([^"]*)"\s+"([^"]*)"', line)
        if not m:
            return None
        ip, when, req, status, size, ref, ua = m.groups()
        method, path, proto = (req.split(" ") + ["", ""])[:3]
        return {"ip": ip, "when": when, "method": method, "path": path,
                "status": int(status), "size": int(size), "referer": ref,
                "ua": ua}

    def analyze_log(self, log_lines: List[str]) -> List[Dict]:
        for line in log_lines:
            rec = self.parse_line(line)
            if not rec:
                continue
            self.parsed.append(rec)
            matches = []
            for pat, label in BOT_PATTERNS:
                if re.search(pat, rec["ua"], re.IGNORECASE):
                    matches.append(label)
            if "python-requests" in rec["ua"].lower():
                matches.append("no-browser-fingerprint")
            suspicious_path = (
                re.search(r"(\.env|\.git/config|/admin|/wp-login|\.json$)",
                          rec["path"], re.IGNORECASE) is not None
            )
            if matches or suspicious_path:
                self.flagged.append({
                    "rec": rec,
                    "matches": matches,
                    "suspicious_path": suspicious_path,
                    "flagged_ts": time.time(),
                })
        return self.flagged

    def stats(self) -> Dict:
        by_ua = {}
        for f in self.flagged:
            ua = f["rec"]["ua"]
            by_ua[ua] = by_ua.get(ua, 0) + 1
        return {
            "total_requests": len(self.parsed),
            "total_flagged": len(self.flagged),
            "flagging_rate_pct": round(len(self.flagged) / max(1, len(self.parsed)) * 100, 1),
            "top_uas": sorted(by_ua.items(), key=lambda kv: kv[1], reverse=True)[:5],
        }


def generate_tarpit_page(token: str, host: str = "internal.corp") -> str:
    """Generate a benign prompt-injection decoy page for tarpit serving."""
    return CANARY_DECOY_HTML.format(token=token, HOST=host)


# ---------------------------------------------------------------------------
# 4. Correlation into timeline + bite stats
# ---------------------------------------------------------------------------

def correlate_events(deploy_events: List[Dict],
                     git_events: List[Dict],
                     tarpit_flags: List[Dict],
                     token_trips: List[Dict]) -> Dict:
    """Correlate all deception events into a timeline."""
    events = []
    events.extend(deploy_events)
    events.extend(git_events)
    events.extend(tarpit_flags)
    events.extend(token_trips)
    events.sort(key=lambda e: e.get("ts", 0))
    return {
        "timeline": events,
        "event_count": len(events),
        "by_type": _count_by_type(events),
    }


def _count_by_type(events: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        t = e.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


def tarpit_bite_stats(tarpit_flags: List[Dict]) -> Dict:
    """Tarpit-bite statistics: total served decoy bites."""
    ips = [f.get("ip", f.get("rec", {}).get("ip", "?"))
           for f in tarpit_flags]
    unique_ips = len(set(ips))
    return {
        "total_bites": len(tarpit_flags),
        "unique_ips_bitten": unique_ips,
        "top_targets": _top_targets(tarpit_flags),
    }


def _top_targets(flags: List[Dict]) -> List[Tuple[str, int]]:
    targets: Dict[str, int] = {}
    for f in flags:
        p = f.get("path", f.get("rec", {}).get("path", "?"))
        targets[p] = targets.get(p, 0) + 1
    return sorted(targets.items(), key=lambda kv: kv[1], reverse=True)[:5]


# ---------------------------------------------------------------------------
# Sample request log for the offline demo
# ---------------------------------------------------------------------------

SAMPLE_REQUEST_LOG = [
    '203.0.113.7 - - [05/Sep/2026:10:00:01 +0000] "GET /docs HTTP/1.1" 200 4312 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36"',
    '198.51.100.9 - - [05/Sep/2026:10:00:03 +0000] "GET /docs HTTP/1.1" 200 4312 "-" "Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"',
    '203.0.113.44 - - [05/Sep/2026:10:00:04 +0000] "GET /admin HTTP/1.1" 403 182 "-" "python-requests/2.31.0"',
    '198.51.100.9 - - [05/Sep/2026:10:00:06 +0000] "GET /.env HTTP/1.1" 200 209 "-" "Mozilla/5.0 (compatible; ClaudeBot/1.0; +https://anthropic.com/claudebot)"',
    '203.0.113.9 - - [05/Sep/2026:10:00:10 +0000] "GET /docs HTTP/1.1" 200 4312 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X) Firefox/121.0"',
    '45.91.22.10 - - [05/Sep/2026:10:00:15 +0000] "GET /wp-login.php HTTP/1.1" 404 154 "-" "curl/8.4.0"',
]


# ---------------------------------------------------------------------------
# 5. Main offline demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 70)
    print("  F10 — Deception Grid v2 — Offline Demo")
    print("=" * 70)

    # [1] Canary generation & deployment
    print("\n[1] Canary Generator & Deployer")
    deployer = CanaryDeployer()
    deployed = deployer.deploy(
        ["web_creds", "db_config", "ci_log", "cd_endpoint", "web_creds"])
    print(f"    Deployed {len(deployed)} tokens:")
    for t in deployed:
        print(f"      - {t.kind:<18} id={t.token_id[:10]}  "
              f"tripwire={t.tripwire}")
    print(f"    Total tokens: {len(deployer.tokens)}")

    # [2] Fake internal git server simulation
    print("\n[2] Fake Internal Git Server (SIMULATION)")
    git_srv = FakeGitServer(deployed[:2])
    clone = git_srv.clone(requester="203.0.113.44")
    print(f"    Git clone triggered canary event by {clone['event']['requester']}")
    print("    Laced commit content (first 2 lines):")
    for line in clone["content"].splitlines()[:2]:
        print(f"      {line}")
    print(f"    Clone log entries: {len(git_srv.clone_log)}")

    # [3] Tarpit detector on sample request log
    print("\n[3] Web Tarpit Detector (AI-crawler flagging)")
    detector = TarpitDetector()
    flagged = detector.analyze_log(SAMPLE_REQUEST_LOG)
    print(f"    Parsed {len(detector.parsed)} requests, "
          f"flagged {len(flagged)} as suspicious:")
    for f in flagged:
        print(f"      - {f['rec']['ip']:<16} {f['rec']['path']:<18} "
              f"UA={f['rec']['ua'][:38]!r} matches={f['matches']}")
    st = detector.stats()
    print(f"    Stats: requests={st['total_requests']} "
          f"flag_rate={st['flagging_rate_pct']}%")
    for ua, n in st["top_uas"]:
        print(f"      top UA: {ua[:48]!r} x{n}")

    # [4] Generate tarpit (prompt-injection decoy) page
    print("\n[4] Tarpit Decoy Page (prompt-injection HTML)")
    token = deployer.tokens[0]
    page = generate_tarpit_page(token.payload, host="internal.corp")
    print(f"    Generated {len(page)}-char decoy page:")
    print(page[:220])

    # [5] Correlate events into timeline + bite stats
    print("\n[5] Correlated Deception Timeline & Bite Stats")
    tarpit_flags = [{"type": "tarpit_bite", "ts": f["flagged_ts"],
                     "ip": f["rec"]["ip"], "path": f["rec"]["path"],
                     "ua": f["rec"]["ua"]} for f in flagged]
    deploy_events = [{"type": "canary_deployed", "ts": t.seeded_at,
                      "kind": t.kind, "token": t.payload}
                     for t in deployed]
    git_events = [{"type": "fake_git_clone", "ts": e["ts"],
                   "ip": e["requester"]} for e in git_srv.clone_log]

    timeline = correlate_events(deploy_events, git_events, tarpit_flags, [])
    print(f"    Total correlated events: {timeline['event_count']}")
    for t in timeline["by_type"].items():
        print(f"      {t[0]:<20} -> {t[1]}")
    print("    First 3 timeline entries:")
    for entry in timeline["timeline"][:3]:
        print(f"      [{entry.get('type')}] ts={entry.get('ts'):.2f} "
              f"{entry.get('ip','')} {entry.get('kind','')}")

    bites = tarpit_bite_stats(tarpit_flags)
    print(f"\n    Tarpit-bite statistics:")
    print(f"      total bites       : {bites['total_bites']}")
    print(f"      unique IPs bitten : {bites['unique_ips_bitten']}")
    print(f"      top targets       : {bites['top_targets']}")

    print("\n" + "=" * 70)
    print("  All modules exercised. Demo complete.")
    print("=" * 70)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
