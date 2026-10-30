python -c "
import pandas as pd
from pathlib import Path
from core.self_healing_loop import MariaSelfHealingOrchestrator

orchestrator = MariaSelfHealingOrchestrator()
csv_file = Path('scenarios/1_hepatitis_b_lcms_messy.csv')
manifest = orchestrator.execute_workflow('scenario_1', csv_file)
print('STATUS:', manifest['final_status'])
for a in manifest['attempts']:
    print(f'Attempt {a[\"attempt_number\"]}: exit={a[\"exit_code\"]} status={a[\"status\"]}')
    if a['stderr']:
        print('STDERR:', a['stderr'][-300:])
"