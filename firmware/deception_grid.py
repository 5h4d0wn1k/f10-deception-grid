#!/usr/bin/env python3
"""
F10 — Deception Grid (decoy orchestration planner).

Plans and scores a defensive deception deployment: given a network model
(legitimate services, host segments, placeholders), it assigns *decoy
inventory* — fake services, honeytokens, and decoy paths — then tracks
engagement events against those decoys and computes an attacker-dwell score
per source (a defensive early-warning metric, NOT an offensive tool).

Deterministic and fully offline - standard library only. All hosts, tokens,
and channels are synthetic placeholders (192.0.2.x, example.com, fake
credentials). Intended ONLY for defense on infrastructure you own or are
authorized to protect.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"

STAGE_ORDER = [
    "primary_touch",
    "credential_use",
    "lateral_move",
    "command_exec",
    "persistence",
    "exfil_stage",
]

DECOY_KINDS = ("fake_service", "honeytoken", "decoy_path")


# --------------------------------------------------------------------------- #
# Model loading.
# --------------------------------------------------------------------------- #
def load_model(path) -> dict:
    """Load and validate a network model JSON document."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_model(data)


def validate_model(model: dict) -> dict:
    if not isinstance(model, dict):
        raise ValueError("model must be a JSON object")
    for key in ("org", "network", "legitimate_services", "fake_services",
                "honeytokens", "decoy_paths"):
        if key not in model:
            raise ValueError("model missing required field: %s" % key)
    for list_key in ("legitimate_services", "fake_services",
                     "honeytokens", "decoy_paths"):
        if not isinstance(model[list_key], list):
            raise ValueError("model field %s must be a list" % list_key)
    subnets = model.get("subnets", {})
    if not isinstance(subnets, dict):
        raise ValueError("model field subnets must be an object")
    return model


# --------------------------------------------------------------------------- #
# Decoy planner (deterministic).
# --------------------------------------------------------------------------- #
def _decoy_id(prefix: str, *parts: str) -> str:
    clean = "-".join(p.replace(" ", "_") for p in parts
                     if p and str(p).strip())
    return "%s-%s" % (prefix, clean)[:64]


def plan_decoys(model: dict) -> dict:
    """Assign decoy inventory from the model into a deterministic plan.

    Every fake service, honeytoken, and decoy path in the model becomes a
    decoy object with a stable id. Fake services are 'bound' to a decoy IP
    (192.0.2.x TEST-NET), honeytokens are paired to a fake credential file,
    and decoy paths are placed next to a host.
    """
    decoys = []
    for i, svc in enumerate(model["fake_services"], start=1):
        decoys.append({
            "decoy_id": _decoy_id("svc", svc["name"]),
            "kind": "fake_service",
            "service": svc["name"],
            "host": svc["host"],
            "port": int(svc["port"]),
            "proto": svc.get("proto", ""),
            "label": svc.get("label", ""),
            "bait": svc.get("bait", ""),
        })
    for i, h in enumerate(model["honeytokens"], start=1):
        token_kind = h.get("kind", "honeytoken")
        decoys.append({
            "decoy_id": _decoy_id("tok", token_kind, h.get("service", "")),
            "kind": "honeytoken",
            "token_kind": token_kind,
            "service": h.get("service", ""),
            "secret": h.get("secret", h.get("key", h.get("entry", ""))),
            "placed": h.get("placed", ""),
        })
    for i, p in enumerate(model["decoy_paths"], start=1):
        decoys.append({
            "decoy_id": _decoy_id("path", p["path"].strip("/")),
            "kind": "decoy_path",
            "path": p["path"],
            "host": p.get("host", ""),
            "note": p.get("note", ""),
        })

    fake_hosts = {s["host"] for s in model["fake_services"]}
    legit_hosts = {s["host"] for s in model["legitimate_services"]}
    path_hosts = {p.get("host") for p in model["decoy_paths"] if p.get("host")}
    covered = fake_hosts | path_hosts
    total = legit_hosts | fake_hosts | path_hosts

    by_kind = {}
    for d in decoys:
        by_kind[d["kind"]] = by_kind.get(d["kind"], 0) + 1

    return {
        "org": model["org"],
        "network": model["network"],
        "decoys": decoys,
        "summary": {
            "legitimate_services": len(model["legitimate_services"]),
            "fake_services": len(model["fake_services"]),
            "honeytokens": len(model["honeytokens"]),
            "decoy_paths": len(model["decoy_paths"]),
            "total_decoys": len(decoys),
            "by_kind": by_kind,
            "hosts_covered": len(covered),
            "hosts_total": len(total),
        },
    }


# --------------------------------------------------------------------------- #
# Engagement tracking.
# --------------------------------------------------------------------------- #
class EngagementTracker:
    """Records engagement events (hits/beacons on decoys) and orders them."""

    def __init__(self, plan: dict = None):
        self.plan = plan
        self._events = []

    def record(self, src: str, decoy_id: str, event_type: str,
               ts: float, detail: str = "") -> None:
        if event_type not in STAGE_ORDER:
            raise ValueError("unknown event_type %r (choose from %s)"
                             % (event_type, ", ".join(STAGE_ORDER)))
        if self.plan is not None:
            ids = {d["decoy_id"] for d in self.plan["decoys"]}
            if decoy_id not in ids:
                raise ValueError("unknown decoy_id %r" % decoy_id)
        self._events.append({
            "src": src,
            "decoy_id": decoy_id,
            "event_type": event_type,
            "ts": float(ts),
            "detail": detail or decoy_id,
        })

    def add_events(self, events) -> None:
        for ev in events:
            self.record(ev.get("src", "?"),
                        ev.get("decoy_id", ""),
                        ev.get("event_type", ""),
                        ev.get("ts", 0.0),
                        ev.get("detail", ""))

    def timeline(self) -> list:
        return sorted(self._events, key=lambda e: (e["ts"], e["src"]))


def _decoy_kind_map(plan: dict) -> dict:
    return {d["decoy_id"]: d["kind"] for d in plan["decoys"]}


# --------------------------------------------------------------------------- #
# Attacker-dwell scoring (defensive heuristics; deterministic).
# --------------------------------------------------------------------------- #
def attacker_dwell_score(events: list, decoy_kinds: dict) -> dict:
    """Score one attacker's engagement depth/dwell on a 0-100 scale."""
    ts = sorted(e["ts"] for e in events)
    dwell = ts[-1] - ts[0]
    if dwell < 60:
        dwell_pts = 5
    elif dwell < 600:
        dwell_pts = 15
    elif dwell < 3600:
        dwell_pts = 30
    else:
        dwell_pts = 45

    stages = []
    for e in sorted(events, key=lambda x: (x["ts"], x.get("src", ""))):
        if e["event_type"] not in stages:
            stages.append(e["event_type"])
    depth_pts = 10 * min(len(stages), 5)

    kinds = {decoy_kinds.get(e["decoy_id"], "?") for e in events}
    breadth = len(kinds) if len(kinds) > 1 else 1
    breadth_pts = {1: 5, 2: 10, 3: 15}.get(min(breadth, 3), 15)
    exfil_bonus = 10 if "exfil_stage" in stages else 0

    score = min(100, dwell_pts + depth_pts + breadth_pts + exfil_bonus)
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    elif score >= 20:
        severity = "LOW"
    else:
        severity = "INFO"

    return {
        "events": len(events),
        "dwell_seconds": int(dwell),
        "stages": stages,
        "stage_depth": len(stages),
        "breadth_kinds": sorted(kinds),
        "score": score,
        "severity": severity,
    }


def score_engagement(tracker_or_events, plan: dict = None) -> dict:
    events = tracker_or_events
    if isinstance(tracker_or_events, EngagementTracker):
        events = tracker_or_events.timeline()
    kinds = _decoy_kind_map(plan) if plan else {}

    groups = {}
    for e in events:
        groups.setdefault(e["src"], []).append(e)

    attackers = []
    for src in sorted(groups):
        stats = attacker_dwell_score(groups[src], kinds)
        stats["src"] = src
        stats["first_ts"] = min(e["ts"] for e in groups[src])
        stats["last_ts"] = max(e["ts"] for e in groups[src])
        attackers.append(stats)

    return {
        "events_total": len(events),
        "attackers": attackers,
        "mean_score": round(sum(a["score"] for a in attackers) /
                            len(attackers), 1) if attackers else 0.0,
        "max_score": max((a["score"] for a in attackers), default=0),
    }


# --------------------------------------------------------------------------- #
# Demo scenario (synthetic engagement timeline against the planned decoys).
# --------------------------------------------------------------------------- #
def build_demo_scenario(plan: dict) -> list:
    """Assemble a synthetic engagement event list on top of the plan's
    decoy ids (deterministic regardless of id derivation)."""
    d = {x["decoy_id"]: x for x in plan["decoys"]}
    svc_dbid = next(i for i, x in d.items() if x["kind"] == "fake_service")
    tok_dbid = next(i for i, x in d.items() if x["kind"] == "honeytoken")
    path_dbid = next(i for i, x in d.items() if x["kind"] == "decoy_path")

    deep = [
        {"src": "203.0.113.11", "decoy_id": path_dbid,
         "event_type": "primary_touch", "ts": 100.0},
        {"src": "203.0.113.11", "decoy_id": tok_dbid,
         "event_type": "credential_use", "ts": 260.0},
        {"src": "203.0.113.11", "decoy_id": svc_dbid,
         "event_type": "lateral_move", "ts": 900.0},
        {"src": "203.0.113.11", "decoy_id": tok_dbid,
         "event_type": "command_exec", "ts": 2100.0},
        {"src": "203.0.113.11", "decoy_id": path_dbid,
         "event_type": "exfil_stage", "ts": 5400.0},
    ]
    shallow = [
        {"src": "198.51.100.7", "decoy_id": svc_dbid,
         "event_type": "primary_touch", "ts": 150.0},
    ]
    return deep + shallow


# --------------------------------------------------------------------------- #
# Reporting.
# --------------------------------------------------------------------------- #
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_result(plan: dict, tracker: EngagementTracker,
                 gate_threshold: float = 80.0) -> dict:
    engagement = score_engagement(tracker, plan)
    violations = [a["src"] for a in engagement["attackers"]
                  if a["score"] >= gate_threshold]
    return {
        "org": plan["org"],
        "network": plan["network"],
        "plan_summary": plan["summary"],
        "decoys": plan["decoys"],
        "engagements": {
            "events_total": len(tracker.timeline()),
            "timeline": tracker.timeline(),
        },
        "attackers": engagement["attackers"],
        "aggregate": {"mean_score": engagement["mean_score"],
                      "max_score": engagement["max_score"]},
        "gate": {"threshold": gate_threshold,
                 "violations": violations,
                 "verdict": "ACTION" if violations else "MONITOR"},
    }


def render_markdown(result: dict, generated: str) -> str:
    lines = ["# F10 — Deception Grid / decoy orchestration report",
             "",
             "Generated: %s" % generated,
             "",
             "## Network model",
             "Org: **%s** · Network: `%s`" % (result["org"], result["network"]),
             "",
             "## Decoy plan summary",
             ""]
    s = result["plan_summary"]
    lines.append("| Decoy kind | Count |")
    lines.append("|---|---|")
    for kind in ("fake_service", "honeytoken", "decoy_path"):
        lines.append("| %s | %d |" % (kind, s["by_kind"].get(kind, 0)))
    lines.append("| **total** | **%d** |" % s["total_decoys"])
    lines.append("")
    lines.append("Host coverage: %d / %d" % (s["hosts_covered"],
                                             s["hosts_total"]))
    lines.append("")
    lines.append("## Decoy inventory")
    lines.append("")
    lines.append("| id | kind | target | bait/placement |")
    lines.append("|---|---|---|---|")
    for d in result["decoys"]:
        if d["kind"] == "fake_service":
            target = "%s:%d/%s" % (d["host"], d["port"], d["proto"])
            bait = d["bait"]
        elif d["kind"] == "honeytoken":
            target = "%s @ %s" % (d["service"], d["placed"])
            bait = d["secret"]
        else:
            target = "%s @ %s" % (d["path"], d["host"])
            bait = d["note"]
        lines.append("| %s | %s | %s | %s |"
                     % (d["decoy_id"], d["kind"], target, bait))
    lines.append("")

    eng = result["engagements"]
    lines.append("## Engagement timeline (%d events)" % eng["events_total"])
    if eng["timeline"]:
        lines.append("")
        lines.append("| ts | src | decoy | stage |")
        lines.append("|---|---|---|---|")
        for e in eng["timeline"]:
            lines.append("| %.1f | %s | %s | %s |"
                         % (e["ts"], e["src"], e["decoy_id"],
                            e["event_type"]))
        lines.append("")

    lines.append("## Attacker-dwell scoring")
    lines.append("")
    lines.append("| src | events | dwell(s) | depth | kinds | score | severity |")
    lines.append("|---|---|---|---|---|---|---|")
    for a in result["attackers"]:
        lines.append("| %s | %d | %d | %d | %d | %d | %s |"
                     % (a["src"], a["events"], a["dwell_seconds"],
                        a["stage_depth"], len(a["breadth_kinds"]),
                        a["score"], a["severity"]))
    lines.append("")
    ag = result["aggregate"]
    lines.append("Mean dwell score: **%.1f** · Max: **%d**" %
                 (ag["mean_score"], ag["max_score"]))
    g = result["gate"]
    lines.append("")
    lines.append("Gate: **%s** (threshold %s)" %
                 (g["verdict"], g["threshold"]))
    if g["violations"]:
        lines.append("Sources requiring response: %s" %
                     ", ".join(g["violations"]))
    return "\n".join(lines)


def render_json(result: dict, generated: str) -> str:
    out = dict(result)
    out["generated"] = generated
    return json.dumps(out, indent=2)


def _write_report(path, payload: str) -> Path:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(payload, encoding="utf-8")
    return out


# --------------------------------------------------------------------------- #
# CLI.
# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="f10-deception-grid",
        description="Decoy orchestration planner (defensive): plan fake "
                    "services, honeytokens, and decoy paths from a network "
                    "model; track engagements; score attacker dwell time.",
    )
    ap.add_argument("--model", default=None,
                    help="path to a network model JSON "
                         "(default: fixtures/network-model.json)")
    ap.add_argument("--events", default=None,
                    help="path to engagement events JSON (list of events)")
    ap.add_argument("--demo", action="store_true",
                    help="run the offline demo (bundled model + synthetic events)")
    ap.add_argument("--config", default="config.json")
    ap.add_argument("--report", default=None,
                    help="output report path; .json selects JSON format")
    ap.add_argument("--strict", action="store_true",
                    help="exit 1 when gate verdict is ACTION (>= threshold)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args(argv)

    cfg = {}
    cfg_path = Path(args.config)
    if cfg_path.exists():
        try:
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print("[config] parse error in %s" % cfg_path, file=sys.stderr)
            return 2

    report_path = args.report or cfg.get("report") or "reports/report.md"
    gate_threshold = float(cfg.get("gate_threshold", 80.0))
    model_path = args.model or cfg.get("model") or \
        str(FIXTURES_DIR / "network-model.json")

    try:
        model = load_model(model_path)
    except Exception as exc:  # noqa: BLE001
        print("[model] cannot load %s: %s" % (model_path, exc), file=sys.stderr)
        return 2

    demo = args.demo or (args.events is None)
    if demo:
        plan = plan_decoys(model)
        tracker = EngagementTracker(plan)
        tracker.add_events(build_demo_scenario(plan))
        result = build_result(plan, tracker, gate_threshold)
        _print_demo(result, verbose=args.verbose)
        payload = (render_json(result, _now())
                   if report_path.endswith(".json")
                   else render_markdown(result, _now()))
        out_path = _write_report(report_path, payload)
        print("\nReport: %s" % out_path)
        return 0

    # --events file mode
    try:
        events = json.loads(Path(args.events).read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print("[events] cannot load %s: %s" % (args.events, exc),
              file=sys.stderr)
        return 2

    plan = plan_decoys(model)
    tracker = EngagementTracker(plan)
    try:
        tracker.add_events(events)
    except ValueError as exc:
        print("[events] invalid engagement data: %s" % exc, file=sys.stderr)
        return 2
    result = build_result(plan, tracker, gate_threshold)
    payload = (render_json(result, _now())
               if report_path.endswith(".json")
               else render_markdown(result, _now()))
    _write_report(report_path, payload)
    print("F10 engagement analysis: %s attackers scored, max %d (threshold %s), "
          "gate=%s" % (len(result["attackers"]), result["aggregate"]["max_score"],
                       gate_threshold, result["gate"]["verdict"]))
    print("Report: %s" % report_path)
    if args.strict and result["gate"]["verdict"] == "ACTION":
        return 1
    return 0


def _print_demo(result: dict, verbose: bool = False) -> None:
    print("=" * 62)
    print("  F10 - DECEPTION GRID / decoy orchestration planner")
    print("  Offline demo on synthetic model + engagement events")
    print("=" * 62)
    print("  Org      : %s" % result["org"])
    print("  Network  : %s" % result["network"])
    s = result["plan_summary"]
    print("  Plan     : %d decoys (%d fake services, %d honeytokens, "
          "%d decoy paths)" % (s["total_decoys"], s["fake_services"],
                               s["honeytokens"], s["decoy_paths"]))
    print("  Coverage : %d/%d hosts" % (s["hosts_covered"], s["hosts_total"]))
    print("")
    print("  Decoy inventory:")
    for d in result["decoys"]:
        if d["kind"] == "fake_service":
            desc = "%s %s:%d" % (d["proto"], d["host"], d["port"])
        elif d["kind"] == "honeytoken":
            desc = "%s @ %s" % (d["service"], d["placed"])
        else:
            desc = "%s @ %s" % (d["path"], d["host"])
        print("    %-22s %-12s %s" % (d["decoy_id"], d["kind"], desc))
    eng = result["engagements"]
    print("")
    print("  Engagement timeline (%d events):" % eng["events_total"])
    for e in eng["timeline"][:8]:
        print("    %.1f  %-15s %-22s %s" % (e["ts"], e["src"],
                                           e["decoy_id"], e["event_type"]))
    print("")
    print("  Attacker-dwell scoring:")
    for a in result["attackers"]:
        print("    %-15s events=%-3d dwell=%-6ds depth=%-2d score=%-3d %s"
              % (a["src"], a["events"], a["dwell_seconds"], a["stage_depth"],
                 a["score"], a["severity"]))
    ag = result["aggregate"]
    g = result["gate"]
    print("")
    print("  Mean score %.1f  max %d  gate=%s (threshold %s)"
          % (ag["mean_score"], ag["max_score"], g["verdict"], g["threshold"]))
    if g["violations"]:
        print("  ACTION required for: %s" % ", ".join(g["violations"]))
    print("=" * 62)


if __name__ == "__main__":
    sys.exit(main())