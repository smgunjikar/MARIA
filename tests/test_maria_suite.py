from pathlib import Path
from core.gvisor_jail import BlastRadiusZeroJail
from core.self_healing_loop import MariaSelfHealingOrchestrator


def test_all_scenarios_automated():
    jail = BlastRadiusZeroJail()
    orchestrator = MariaSelfHealingOrchestrator(jail=jail)

    scenarios = [
        ("scenario_1", Path("scenarios/1_hepatitis_b_lcms_messy.csv")),
        ("scenario_2", Path("scenarios/2_vendor_audit_poisoned.csv")),
        ("scenario_3", Path("scenarios/3_corrupted_matrix_bomb.csv")),
    ]

    print("=== M.A.R.I.A. AUTOMATED MULTI-SCENARIO TEST SUITE ===")
    for sid, spath in scenarios:
        print(f"\n[TESTING] Dispatching {sid} ({spath.name})...")
        manifest = orchestrator.execute_workflow(scenario_id=sid, csv_path=spath)

        print(f"  -> Final Status: {manifest['final_status']}")
        print(f"  -> Total Attempts: {manifest['total_attempts']}")
        print(f"  -> Manifest SHA-256: {manifest['manifest_sha256'][:16]}...")
        print(f"  -> Active Orphaned Containers: {jail.count_active_sandboxes()}")

        assert jail.count_active_sandboxes() == 0, "Lifecycle discipline violation: Orphaned container detected!"
        if sid in {"scenario_2", "scenario_3"}:
            assert manifest["final_status"] == "CONTAINMENT_TRIGGERED", f"Security failure on {sid}"
        elif sid == "scenario_1":
            assert manifest["final_status"] == "VERIFIED_SUCCESS", f"Self-healing failure on {sid}"

    print("\n✅ ALL MULTI-SCENARIO TESTS PASSED CLEANLY WITH ZERO LEAKS!")


if __name__ == "__main__":
    test_all_scenarios_automated()

