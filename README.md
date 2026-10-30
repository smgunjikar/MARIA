# M.A.R.I.A. 🛡️
### Multi-Agent Recursive Inspection & Audit ("Blast Radius Zero" Execution Firewall)

**M.A.R.I.A.** is a self-hosted, containment-first autonomous code and data-pipeline control plane built for **Vultr: Agent Rush Hackathon (Challenge 1: Blast Radius Zero)**. 

Instead of trusting AI coding agents directly on a server, M.A.R.I.A. acts as an execution firewall: it plans tasks, writes code, self-heals from runtime tracebacks via **Vultr Serverless Inference**, and verifies output integrity inside ephemeral, air-gapped sandboxes—neutralizing indirect prompt injections, secret exfiltration, and memory bombs with zero host impact.

---

## 🏛️ Architecture & Blast Radius Zero Defense-in-Depth

M.A.R.I.A. enforces strict OS- and kernel-level isolation policies on every agent run:
- **Network Air-Gap (`--network none`):** Sandbox containers have zero internet egress or ingress, making data exfiltration impossible.
- **Immutable Root Filesystem (`--read-only`):** Prevents unauthorized file modifications on the host or container image.
- **Hard Resource Cgroups (`--memory 512m --pids-limit 32`):** Defeats fork bombs and memory leaks instantly via `SIGKILL (Exit Code 137 / OOMKilled)`.
- **Sanitized Environment (`-e HOME=/tmp`):** Host API keys (`VULTR_INFERENCE_API_KEY`) remain strictly in host control-plane memory; zero credentials enter the sandbox.
- **Dead-Man's Switch Reaper:** Background daemon thread sweeps and destroys any orphaned container surviving past its execution window.

---

## 📂 Project Structure

```text
maria-vultr/
├── Dockerfile.sandbox            # Pre-baked Python 3.11 ML runtime (pandas, sklearn, xgboost)
├── generate_scenarios.py         # Generates the 3 official judge verification CSVs
├── core/
│   ├── gvisor_jail.py            # Hardened container runner + cgroup telemetry + reaper
│   ├── ast_contract.py           # Static AST data-leakage and artifact verifier
│   └── self_healing_loop.py      # Vultr Serverless Inference + stderr self-healing loop
├── web/
│   ├── main.py                   # FastAPI control plane + host psutil telemetry server
│   └── static/
│       └── index.html            # Dark-mode M.A.R.I.A. control plane dashboard
├── scenarios/                    # Untrusted test datasets (Messy, Poisoned, Bomb)
├── artifacts/                    # Verified output charts & cleaned CSVs with SHA-256 hashes
└── requirements.txt              # Control plane dependencies

