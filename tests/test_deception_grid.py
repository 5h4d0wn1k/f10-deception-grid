import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from firmware.deception_grid import (  # noqa: E402
    EngagementTracker,
    STAGE_ORDER,
    attacker_dwell_score,
    build_demo_scenario,
    build_result,
    load_model,
    main,
    plan_decoys,
    score_engagement,
    validate_model,
)

FIXTURES = os.path.join(os.path.dirname(__file__), "..", "fixtures")
MODEL = os.path.join(FIXTURES, "network-model.json")


def _model():
    return load_model(MODEL)


class ModelTest(unittest.TestCase):
    def test_load_valid_model(self):
        m = _model()
        self.assertEqual(m["org"], "acme-lab.example")
        self.assertEqual(m["network"], "192.0.2.0/24")
        self.assertEqual(len(m["fake_services"]), 5)
        self.assertEqual(len(m["honeytokens"]), 4)
        self.assertEqual(len(m["decoy_paths"]), 6)

    def test_missing_field_rejected(self):
        with self.assertRaises(ValueError):
            validate_model({"org": "x", "network": "192.0.2.0/24"})

    def test_bad_model_exit_two(self):
        with tempfile.TemporaryDirectory() as td:
            bad = os.path.join(td, "bad.json")
            with open(bad, "w") as fh:
                fh.write("{not json")
            code = main(["--model", bad, "--events",
                         os.path.join(td, "e.json")])
            self.assertEqual(code, 2)


class PlannerTest(unittest.TestCase):
    def test_plan_covers_all_fake_inventory(self):
        plan = plan_decoys(_model())
        by_kind = plan["summary"]["by_kind"]
        self.assertEqual(by_kind["fake_service"], 5)
        self.assertEqual(by_kind["honeytoken"], 4)
        self.assertEqual(by_kind["decoy_path"], 6)
        self.assertEqual(plan["summary"]["total_decoys"], 15)

    def test_deterministic_across_calls(self):
        a = plan_decoys(_model())
        b = plan_decoys(_model())
        self.assertEqual([d["decoy_id"] for d in a["decoys"]],
                         [d["decoy_id"] for d in b["decoys"]])

    def test_decoy_ids_unique(self):
        plan = plan_decoys(_model())
        ids = [d["decoy_id"] for d in plan["decoys"]]
        self.assertEqual(len(ids), len(set(ids)))

    def test_kinds_present(self):
        plan = plan_decoys(_model())
        self.assertEqual({d["kind"] for d in plan["decoys"]},
                         {"fake_service", "honeytoken", "decoy_path"})

    def test_fake_service_has_bait(self):
        plan = plan_decoys(_model())
        svc = next(d for d in plan["decoys"]
                   if d["kind"] == "fake_service")
        self.assertTrue(svc["bait"])
        self.assertIn("192.0.2.", str(svc["host"]))


class TrackerTest(unittest.TestCase):
    def setUp(self):
        self.plan = plan_decoys(_model())
        self.svc = next(d for d in self.plan["decoys"]
                        if d["kind"] == "fake_service")

    def test_record_and_timeline_ordering(self):
        t = EngagementTracker(self.plan)
        t.record("203.0.113.11", self.svc["decoy_id"],
                 "primary_touch", 200.0)
        t.record("203.0.113.11", self.svc["decoy_id"],
                 "lateral_move", 100.0)
        tl = t.timeline()
        self.assertEqual(len(tl), 2)
        self.assertEqual([e["ts"] for e in tl], [100.0, 200.0])

    def test_unknown_stage_rejected(self):
        t = EngagementTracker(self.plan)
        with self.assertRaises(ValueError):
            t.record("203.0.113.11", self.svc["decoy_id"],
                     "not-a-stage", 1.0)

    def test_unknown_decoy_rejected(self):
        t = EngagementTracker(self.plan)
        with self.assertRaises(ValueError):
            t.record("203.0.113.11", "svc-nope", "primary_touch", 1.0)

    def test_timeline_sorted_by_src_within_ts(self):
        t = EngagementTracker(self.plan)
        t.record("198.51.100.9", self.svc["decoy_id"], "primary_touch", 5.0)
        t.record("203.0.113.11", self.svc["decoy_id"], "primary_touch", 5.0)
        tl = t.timeline()
        self.assertEqual([e["src"] for e in tl],
                         ["198.51.100.9", "203.0.113.11"])

    def test_valid_stages_all_known(self):
        t = EngagementTracker(self.plan)
        for i, stage in enumerate(STAGE_ORDER):
            t.record("203.0.113.11", self.svc["decoy_id"], stage, float(i))
        self.assertEqual(len(t.timeline()), len(STAGE_ORDER))


class DwellScoreTest(unittest.TestCase):
    def _kinds(self):
        return {d["decoy_id"]: d["kind"]
                for d in plan_decoys(_model())["decoys"]}

    def test_single_touch_is_low(self):
        kinds = self._kinds()
        events = [{"decoy_id": "svc-x", "event_type": "primary_touch",
                   "ts": 10.0}]
        r = attacker_dwell_score(events, kinds)
        self.assertEqual(r["severity"], "LOW")
        self.assertLess(r["score"], 40)

    def test_deep_progression_is_critical(self):
        kinds = self._kinds()
        events = []
        for i, stage in enumerate(STAGE_ORDER):
            events.append({"decoy_id": "svc-x", "event_type": stage,
                           "ts": float(i * 600)})
        r = attacker_dwell_score(events, kinds)
        self.assertGreaterEqual(r["score"], 80)
        self.assertEqual(r["severity"], "CRITICAL")

    def test_scenario_scores(self):
        plan = plan_decoys(_model())
        tracker = EngagementTracker(plan)
        tracker.add_events(build_demo_scenario(plan))
        eng = score_engagement(tracker, plan)
        self.assertEqual(eng["events_total"], 6)
        by_src = {a["src"]: a for a in eng["attackers"]}
        self.assertEqual(eng["max_score"],
                         by_src["203.0.113.11"]["score"])
        self.assertTrue(by_src["203.0.113.11"]["score"]
                        > by_src["198.51.100.7"]["score"])
        self.assertEqual(by_src["203.0.113.11"]["severity"], "CRITICAL")

    def test_attacker_aggregation(self):
        kinds = self._kinds()
        events = [{"decoy_id": "svc-x", "event_type": "primary_touch",
                   "ts": 1.0, "src": "203.0.113.11"},
                  {"decoy_id": "svc-x", "event_type": "lateral_move",
                   "ts": 2.0, "src": "203.0.113.11"}]
        eng = score_engagement(events, plan_decoys(_model()))
        self.assertEqual(len(eng["attackers"]), 1)
        self.assertEqual(eng["attackers"][0]["events"], 2)


class ResultTest(unittest.TestCase):
    def test_gate_violations(self):
        plan = plan_decoys(_model())
        tracker = EngagementTracker(plan)
        tracker.add_events(build_demo_scenario(plan))
        res = build_result(plan, tracker, gate_threshold=80.0)
        self.assertIn("203.0.113.11", res["gate"]["violations"])
        self.assertEqual(res["gate"]["verdict"], "ACTION")

    def test_no_violations_high_threshold(self):
        plan = plan_decoys(_model())
        tracker = EngagementTracker(plan)
        tracker.add_events(build_demo_scenario(plan))
        res = build_result(plan, tracker, gate_threshold=101.0)
        self.assertEqual(res["gate"]["violations"], [])
        self.assertEqual(res["gate"]["verdict"], "MONITOR")


class CliTest(unittest.TestCase):
    def test_demo_exit_zero(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "demo.json")
            code = main(["--demo", "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                data = json.loads(fh.read())
            self.assertEqual(data["plan_summary"]["total_decoys"], 15)

    def test_demo_markdown_report(self):
        with tempfile.TemporaryDirectory() as td:
            rp = os.path.join(td, "demo.md")
            code = main(["--demo", "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                text = fh.read()
            self.assertIn("Decoy plan summary", text)
            self.assertIn("203.0.113.11", text)

    def test_events_file_mode(self):
        plan = plan_decoys(_model())
        tracker = EngagementTracker(plan)
        events = build_demo_scenario(plan)[:2]
        with tempfile.TemporaryDirectory() as td:
            ep = os.path.join(td, "events.json")
            with open(ep, "w") as fh:
                json.dump(events, fh)
            rp = os.path.join(td, "out.json")
            code = main(["--events", ep, "--report", rp])
            self.assertEqual(code, 0)
            with open(rp) as fh:
                data = json.loads(fh.read())
            self.assertEqual(data["engagements"]["events_total"], 2)

    def test_strict_gate_exit_one(self):
        plan = plan_decoys(_model())
        tracker = EngagementTracker(plan)
        tracker.add_events(build_demo_scenario(plan))
        events = [{"src": e["src"], "decoy_id": e["decoy_id"],
                   "event_type": e["event_type"], "ts": e["ts"]}
                  for e in tracker.timeline()]
        with tempfile.TemporaryDirectory() as td:
            ep = os.path.join(td, "ev.json")
            with open(ep, "w") as fh:
                json.dump(events, fh)
            rp = os.path.join(td, "o.json")
            code = main(["--events", ep, "--report", rp, "--strict"])
            self.assertEqual(code, 1)

    def test_bad_events_exit_two(self):
        with tempfile.TemporaryDirectory() as td:
            ep = os.path.join(td, "ev.json")
            with open(ep, "w") as fh:
                json.dump([{"src": "203.0.113.11", "decoy_id": "svc-x",
                            "event_type": "nope", "ts": 1.0}], fh)
            rp = os.path.join(td, "o.md")
            code = main(["--events", ep, "--report", rp])
            self.assertEqual(code, 2)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as cm:
            main(["--help"])
        self.assertEqual(cm.exception.code, 0)


if __name__ == "__main__":
    unittest.main()