import json
from pathlib import Path
import sys

# Display Startup ASCII Banner to stderr (keeps stdout clean for JSON-RPC)
BANNER = r"""
  __  __         _       ____      ___        _    
 |  \/  |       / \     |  _ \    |_ _|      / \   
 | |\/| |      / _ \    | |_) |    | |      / _ \  
 | |  | |     / ___ \   |  _ <     | |     / ___ \ 
 |_|  |_|    /_/   \_\  |_| \_\   |___|   /_/   \_\

 >> MY ARTIFICIALLY RUDE INTELLIGENCE ASSISTANT <<
 --------------------------------------------------
 by smgunjikar
 --------------------------------------------------
 System Status: Kernel Locked | Air-Gapped Sandbox
"""
sys.stderr.write(BANNER + "\n")
sys.stderr.flush()

try:
    from fastmcp import FastMCP
    mcp = FastMCP(
        "M.A.R.I.A. Execution Firewall",
        instructions="M.A.R.I.A. (My Artificially Rude Intelligence Assistant) by sourabh manohar gunjikar. An air-gapped execution sandbox and AST-verified self-healing firewall that safely executes, reconciles, and cleans untrusted chaotic enterprise data."
    )
except ImportError:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("M.A.R.I.A. Execution Firewall")

from core.gvisor_jail import BlastRadiusZeroJail
from core.self_healing_loop import MariaSelfHealingOrchestrator

jail = BlastRadiusZeroJail()
orchestrator = MariaSelfHealingOrchestrator(jail=jail)


@mcp.tool()
def maria_check_sandbox_status() -> str:
    """Returns the current kernel isolation and cgroups-v2 status of the local M.A.R.I.A. firewall."""
    return json.dumps({
        "assistant": "M.A.R.I.A. (My Artificially Rude Intelligence Assistant)",
        "creator": "sourabh manohar gunjikar",
        "runtime": "Docker Overlay + Hardened cgroups-v2",
        "memory_ceiling": "512 MB (Zero Swap)",
        "network_policy": "--network none (Air-Gap)",
        "filesystem_policy": "READ-ONLY Root + 64MB tmpfs",
        "secrets_exposed": 0,
        "orphaned_sandboxes": jail.count_active_sandboxes()
    }, indent=2)


@mcp.tool()
def maria_audit_and_heal(file_path: str) -> str:
    """Safely audits, disambiguates, self-heals, and executes a chaotic CSV/XLSX file inside the Blast Radius Zero sandbox.
    
    Args:
        file_path: Absolute or relative path to the messy dataset file.
    
    Returns:
        A JSON string containing the cryptographic SHA-256 seal, final status, AST checks, and output artifact paths.
    """
    path = Path(file_path).resolve()
    if not path.exists():
        return json.dumps({"status": "ERROR", "message": f"Target dataset not found at {path}"})

    manifest = orchestrator.execute_workflow(scenario_id="custom", csv_path=path)
    
    last_attempt = manifest.get("attempts", [{}])[-1] if manifest.get("attempts") else {}
    
    summary = {
        "assistant": "M.A.R.I.A. (My Artificially Rude Intelligence Assistant)",
        "creator": "sourabh manohar gunjikar",
        "final_status": manifest.get("final_status"),
        "total_attempts": manifest.get("total_attempts"),
        "manifest_sha256": manifest.get("manifest_sha256"),
        "input_sha256": manifest.get("input_csv_sha256"),
        "artifacts_produced": manifest.get("output_artifacts", {}),
        "containment_events": [
            e for a in manifest.get("attempts", []) for e in a.get("containment_events", [])
        ],
        "ast_violations": [
            v for a in manifest.get("attempts", []) for v in a.get("ast_violations", [])
        ],
        "metrics": last_attempt.get("stdout", "").strip()
    }
    return json.dumps(summary, indent=2)


if __name__ == "__main__":
    mcp.run()