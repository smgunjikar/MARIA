import os
import shutil
import tempfile
from pathlib import Path
import psutil
from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse

from core.gvisor_jail import BlastRadiusZeroJail
from core.self_healing_loop import MariaSelfHealingOrchestrator

app = FastAPI(
    title="M.A.R.I.A. | Blast Radius Zero Control Plane",
    description="Multi-Agent Recursive Inspection & Audit on Vultr Cloud Compute",
    version="2.0.0",
)

jail = BlastRadiusZeroJail()
orchestrator = MariaSelfHealingOrchestrator(jail=jail)

SCENARIO_FILES = {
    "scenario_1": Path("scenarios/1_hepatitis_b_lcms_messy.csv"),
    "scenario_2": Path("scenarios/2_vendor_audit_poisoned.csv"),
    "scenario_3": Path("scenarios/3_corrupted_matrix_bomb.csv"),
}


@app.get("/api/host-telemetry")
def get_host_telemetry():
    vm = psutil.virtual_memory()
    has_key = bool(os.environ.get("VULTR_INFERENCE_API_KEY", "").strip())
    return {
        "host_cpu_percent": psutil.cpu_percent(interval=0.1),
        "host_ram_used_gb": round(vm.used / (1024 ** 3), 2),
        "host_ram_total_gb": round(vm.total / (1024 ** 3), 2),
        "host_ram_percent": vm.percent,
        "active_orphaned_containers": jail.count_active_sandboxes(),
        "sandbox_runtime": "gVisor (runsc)" if jail.has_gvisor else "Docker Overlay + Hardened cgroups-v2",
        "vultr_inference_mode": "LIVE ([api.vultrinference.com/v1](https://api.vultrinference.com/v1))" if has_key else "READY (Deterministic Fallback Active)",
        "sandbox_caps": {
            "memory_mb": jail.memory_limit_mb,
            "pids_limit": jail.pids_limit,
            "network": "NONE (Air-Gapped)",
            "filesystem": "READ-ONLY + 64MB noexec tmpfs",
            "secrets_exposed": 0,
        },
    }


@app.get("/api/scenario-preview/{scenario_id}")
def get_scenario_preview(scenario_id: str):
    if scenario_id not in SCENARIO_FILES:
        raise HTTPException(status_code=404, detail="Unknown scenario_id")
    csv_path = SCENARIO_FILES[scenario_id]
    lines = csv_path.read_text(encoding="utf-8").splitlines()[:8]
    return {"filename": csv_path.name, "preview_lines": lines}


@app.post("/api/run-scenario/{scenario_id}")
def run_scenario(scenario_id: str):
    if scenario_id not in SCENARIO_FILES:
        raise HTTPException(status_code=404, detail="Unknown scenario_id")
    csv_path = SCENARIO_FILES[scenario_id]
    if not csv_path.exists():
        raise HTTPException(status_code=500, detail=f"Scenario file missing: {csv_path}")
    manifest = orchestrator.execute_workflow(scenario_id=scenario_id, csv_path=csv_path)
    return manifest


@app.get("/artifacts/{run_id}/{filename}")
def get_artifact(run_id: str, filename: str):
    safe_run = Path(run_id).name
    safe_file = Path(filename).name
    target = Path("artifacts") / safe_run / safe_file
    if not target.exists():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(target)


@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_file = Path("web/static/index.html")
    return index_file.read_text(encoding="utf-8")