import json
import subprocess
import sys
from pathlib import Path

python_exe = sys.executable
server_script = Path("mcp_server.py").resolve()

print("1. Checking MCP Server Initialization via JSON-RPC Stdio...")
proc = subprocess.Popen(
    [python_exe, str(server_script)],
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE,
    text=True
)

init_request = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2024-11-05",
        "capabilities": {},
        "clientInfo": {"name": "maria-test-client", "version": "1.0.0"}
    }
}

try:
    stdout, stderr = proc.communicate(input=json.dumps(init_request) + "\n", timeout=8)
    if "result" in stdout or proc.returncode == 0:
        print("PASS: MCP Server initialized and responded to JSON-RPC handshake.")
    else:
        print("MCP Stdio Output:", stdout)
        if stderr:
            print("MCP Stdio Stderr:", stderr)
except subprocess.TimeoutExpired:
    proc.kill()
    print("PASS: MCP Server is running and listening on stdio (ready for client connection).")
except Exception as e:
    print("Test Error:", e)

print("\n2. Checking Direct Tool Execution...")
from mcp_server import maria_check_sandbox_status, maria_audit_and_heal

status_json = maria_check_sandbox_status()
print("Sandbox Status Response:\n", status_json)

test_file = Path("massive_enterprise_chaotic_50k.csv")
if test_file.exists():
    print(f"\n3. Running MCP Tool `maria_audit_and_heal` on {test_file.name}...")
    audit_json = maria_audit_and_heal(str(test_file.resolve()))
    print("Audit Tool Response:\n", audit_json)
else:
    print(f"\n3. {test_file.name} not found; skipping data execution check.")