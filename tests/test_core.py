import os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from croptimizer import scoring, fair, optimizer, verify, pipeline, signals

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "sample-data")


def test_priority_known_answer():
    f = {"cvss": 8.0, "epss": 0.5}
    assert scoring.finding_priority(f, 5, 1.5) == 5 * 8.0 * 0.5 * 1.5 == 30.0


def test_threat_multiplier_bounds():
    a = lambda n: [{"agent": {"name": "H"}, "rule": {"level": 12}}] * n
    assert scoring.threat_multiplier(a(0), "H") == 1.0
    assert scoring.threat_multiplier(a(50), "H") == 2.0
    assert scoring.threat_multiplier(a(5), "OTHER") == 1.0


def test_enterprise_score_monotonic_and_bounded():
    assert scoring.enterprise_score([], 100) == 0
    assert scoring.enterprise_score([10], 100) < scoring.enterprise_score([10, 10], 100) < 100


def test_pert_within_bounds_and_seeded():
    rng = random.Random(1)
    xs = [fair.pert(rng, 10, 20, 50) for _ in range(2000)]
    assert min(xs) >= 10 and max(xs) <= 50
    sc = [{"id": "x", "aro": [0.1, 0.2, 0.5], "sle": [1, 2, 5]}]
    assert fair.simulate(sc, 50, 9) == fair.simulate(sc, 50, 9)


def test_overlap_not_additive():
    base = {"cred": 100.0}
    eff = {"a": {"cred": 0.5}, "b": {"cred": 0.5}}
    assert optimizer.exposure(["a", "b"], base, eff) == 25.0          # not 0
    assert optimizer.naive_additive_reduction(["a", "b"], base, eff) == 100.0  # the flaw
    assert optimizer.exposure(["a"], base, eff) == 50.0


def test_optimizer_known_answer_and_budget():
    base = {"s1": 100.0, "s2": 60.0}
    fixes = [{"id": "a", "name": "A", "cost": 10}, {"id": "b", "name": "B", "cost": 10},
             {"id": "c", "name": "C", "cost": 15}]
    eff = {"a": {"s1": 0.5}, "b": {"s1": 0.5}, "c": {"s2": 0.5}}
    sol = optimizer.solve(base, fixes, eff, 25)
    # a+b overlap (reduction 75); a+c (or b+c) have no overlap: 50+30 = 80, so the optimizer prefers them
    assert set(sol["fixes"]) == {"a", "c"} or set(sol["fixes"]) == {"b", "c"}
    assert sol["cost"] <= 25 and abs(sol["reduction"] - 80.0) < 1e-9
    assert optimizer.solve(base, fixes, eff, 5)["fixes"] == []
    assert set(optimizer.solve(base, fixes, eff, 20)["fixes"]) == {"a", "b"}  # only pair that fits


def test_verify_outcomes():
    t = {"test_id": "T1", "name": "n", "host": "H", "expected_before": "detected", "expected_after": "blocked",
         "detect_rules": ["1"], "block_rules": ["2"]}
    mk = lambda rid: [{"agent": {"name": "H"}, "rule": {"id": rid, "level": 10, "mitre": {"id": ["T1"]}}}]
    assert verify.observe(t, []) == "missed"
    assert verify.observe(t, mk("1")) == "detected"
    assert verify.observe(t, mk("2")) == "blocked"
    assert verify.verify([t], mk("1"), mk("2"))[0]["verified"] is True


def test_pipeline_end_to_end_and_reproducible():
    r1 = pipeline.run(DATA, 50000, seed=42, with_sensitivity=False)
    r2 = pipeline.run(DATA, 50000, seed=42, with_sensitivity=False)
    assert r1["exposure_after"] == r2["exposure_after"]
    assert r1["recommendation"]["cost"] <= 50000
    assert r1["exposure_after"]["mean"] < r1["exposure_before"]["mean"]
    assert r1["score"]["after"] < r1["score"]["before"]
    assert r1["recommendation"]["reduction_naive_claim"] >= r1["recommendation"]["reduction_correct"]


def test_blended_score_never_zero_with_residual_exposure():
    assert scoring.blended_score(0.0, 100000, 250000, 0.6) > 10
    assert scoring.blended_score(0.0, 0.0, 250000, 0.6) == 0.0
    assert scoring.blended_score(80, 300000, 250000, 0.6) > scoring.blended_score(80, 100000, 250000, 0.6)


def test_pipeline_score_nonzero_at_high_budget():
    r = pipeline.run(DATA, 150000, seed=42, with_sensitivity=False)
    assert r["score"]["after"] > 0 and r["score"]["after"] < r["score"]["before"]


def test_signal_multiplier_known_answer_and_cap():
    assert signals.multiplier(0, 10) == 1.0
    assert signals.multiplier(5, 10) == 1.5
    assert signals.multiplier(99, 10) == 2.0


def test_alerts_raise_declared_frequency():
    sc = [{"id": "x", "aro": [0.1, 0.2, 0.4], "signals": {"techniques": ["T1003"]}}]
    cfg = {"signal_min_level": 7, "alerts_for_max_signal": 10}
    al = [{"agent": {"name": "H"}, "rule": {"level": 12, "mitre": {"id": ["T1003.001"], "tactic": []}}}] * 5
    adj, d = signals.adjust_scenarios(sc, al, cfg)
    assert d["x"]["alerts"] == 5
    assert all(abs(a - b) < 1e-9 for a, b in zip(adj[0]["aro"], [0.15, 0.30, 0.60]))
    low = [{"agent": {"name": "H"}, "rule": {"level": 3, "mitre": {"id": ["T1003"], "tactic": []}}}] * 5
    assert signals.count_signals(low, sc, 7)["x"] == 0
