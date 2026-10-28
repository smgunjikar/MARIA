from pathlib import Path
from core.self_healing_loop import MariaSelfHealingOrchestrator

orch = MariaSelfHealingOrchestrator()
result = orch.execute_workflow("scenario_1", Path("scenarios/1_hepatitis_b_lcms_messy.csv"))

print(f"Workflow: {result['scenario_name']}")
print(f"Final Status: {result['final_status']} | Total Attempts: {result['total_attempts']}")
print(f"Manifest SHA-256: {result['manifest_sha256']}\n")

for att in result["attempts"]:
    print(f"--- Attempt {att['attempt_number']} ({att['run_id']}) -> {att['status']} (Exit: {att['exit_code']}, {att['duration_ms']}ms, Peak RAM: {att['peak_memory_mb']} MB) ---")
    if att["stderr"]:
        print("  STDERR Captured:", att["stderr"].strip().splitlines()[-1])
    if att["stdout"]:
        print("  STDOUT:", att["stdout"].strip())

print("\nGenerated Artifacts inside ./artifacts/" + result["artifact_run_id"] + ":")
for fname, sha in result["output_artifacts"].items():
    print(f"  [FILE] {fname} (SHA-256: {sha[:16]}...)")
