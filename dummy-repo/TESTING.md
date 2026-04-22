# Raven Platform — End-to-End Testing Guide

This guide walks you through testing the **LangGraph + AGP mitigation
pipeline** end-to-end using this `dummy-repo` as the target.

> **TL;DR**
> 1. `git push` this repo to a Git host (or use a local file:// URL)
> 2. Boot the Raven Platform stack (`docker-compose up`)
> 3. Create a project that points at this repo
> 4. Run a SAST scan → kick off mitigation → watch the swarm + AGP loop work

---

## 0 · Prerequisites

| Tool | Why |
|---|---|
| Docker + docker-compose | run Raven backend + this app for DAST |
| Python 3.13 | run backend tests directly (optional) |
| Node.js 18+ | run the Express vulnerable app (optional) |
| `git` | the platform clones target repos |
| A SonarCloud / SonarQube account | for SAST results |
| (Optional) An OpenAI / Azure / Anthropic API key | for the fixer LLM |

---

## 1 · Push the dummy-repo to a Git host

The Raven Platform clones the target repo, so it must be reachable.

```powershell
cd "C:\Users\SunilKumarPradhan\Desktop\Master Folder\RavenProject\scanner-demo\dummy-repo"
git init -b main
git add .
git commit -m "vulnerable demo repo"

# push to GitHub (replace with your fork)
git remote add origin https://github.com/<you>/raven-vulnerable-demo.git
git push -u origin main
```

If you don't want to push, you can use a **local file URL** in the
project config later:
`file:///C:/Users/SunilKumarPradhan/Desktop/Master Folder/RavenProject/scanner-demo/dummy-repo`

---

## 2 · Boot the Raven Platform stack

```powershell
cd "C:\Users\SunilKumarPradhan\Desktop\Master Folder\RavenProject\raven-platform"

# install python dependencies for the new AGP modules
cd backend
pip install -e .

# OR with uv (preferred):
uv pip install -e .

# back to root + start the stack
cd ..
docker-compose -f docker-compose.dev.yml up -d
```

Verify the backend is up:

```powershell
curl http://localhost:8000/healthz
curl http://localhost:8000/docs   # OpenAPI UI
```

The frontend should be on http://localhost:3000.

---

## 3 · (Optional) Boot the live targets for DAST

If you want to run **DAST/ZAP** scans against the demo apps:

```powershell
cd "C:\Users\SunilKumarPradhan\Desktop\Master Folder\RavenProject\scanner-demo\dummy-repo"
docker compose up -d
```

Now you have:
- Flask app  →  http://localhost:5000
- Express app →  http://localhost:3000

Quick sanity check that they're vulnerable (Flask):

```powershell
# SQLi via login (returns 500 with stack trace)
curl -X POST http://localhost:5000/login -d "username=' OR 1=1 --&password=x"

# command injection via /api/admin/exec
curl -X POST http://localhost:5000/api/admin/exec -H "Content-Type: application/json" -d '{"cmd":"whoami"}'

# missing security headers
curl -I http://localhost:5000/
```

---

## 4 · Create the project in Raven

Through the Raven UI (http://localhost:3000):

1. **Sign in** as the seeded admin user.
2. **Projects → New project**:
   - Name: `vulnerable-demo`
   - Repo URL: the URL from step 1
   - Default branch: `main`
3. **Mitigator → Configurations → New**:
   - Name: `default-config`
   - LLM provider: OpenAI / Azure (your choice)
   - Model: `gpt-4o-mini` (or any chat model)
   - API key: paste it
4. **Save** — the config is encrypted at rest.

---

## 5 · Run a SAST scan

UI: **Scans → New scan**

| Field | Value |
|---|---|
| Project | `vulnerable-demo` |
| Scan type | `SAST` |
| Engine | SonarQube / SonarCloud |
| Branch | `main` |

Or via API:

```powershell
$body = @{
  project_id = "<uuid-of-vulnerable-demo>"
  scan_type = "SAST"
  branch = "main"
} | ConvertTo-Json
curl -X POST http://localhost:8000/api/v1/scans `
  -H "Authorization: Bearer <token>" `
  -H "Content-Type: application/json" `
  -d $body
```

Wait for `status = COMPLETED`. You should see ~30+ findings spread
across `vulnerable-flask-app/`, `vulnerable-express-app/`, the original
`python-tool/` and `website/`.

---

## 6 · Kick off the LangGraph mitigation

UI: **Mitigator → New session → pick the scan above**

What you should observe (WebSocket progress events stream live):

| Phase | What you should see |
|---|---|
| `analyzing` | Analyser parses scan results into `vulnerabilities` |
| `context_gathering` | **Deep file tracing** — for `/login` it pulls in `routes/auth.py` + `services/user_service.py` + `services/db.py` + `config.py` + `middleware/auth_middleware.py` |
| `fixing` | The swarm fans out via `Send()` → you'll see logs from `injection_fixer`, `header_fixer`, `auth_fixer`, `general_fixer` running in parallel |
| `peer_review` | `peer_reviewer` cross-checks each fix |
| `validating` | Syntax + size + LLM review |
| `waiting_review` | Pauses for you (uses `interrupt()`) |

---

## 7 · Verify the AGP self-evolution kicks in

After the **first iteration**, look in the backend logs for:

```
[session=...] AGP SEPL: evolved N resources: ['prompt:injection_fixer', ...]
```

This proves:
1. **RSPL** — the prompts were registered as `ProtocolResource`s
2. **SEPL** — `EvolutionEngine.evolve_underperforming()` decided the
   metrics were below the 50%/0.5 threshold and triggered a propose →
   assess → commit cycle.

To inspect lineage, query the checkpoint:

```sql
SELECT state_snapshot->'agp' FROM mitigation_checkpoints
WHERE session_id = '<your-session-id>'
ORDER BY iteration DESC LIMIT 1;
```

You should see:
- `registry_snapshot` — all registered resources with version numbers
- `evolution_summary` — `"Evolution Engine: N cycles (X committed, Y rolled back)"`
- `evolution_history` — last 20 evolution records

Each proposed fix in the DB also carries `agp_agent_version` and
`agp_prompt_hash` columns (added by the fixer pipeline) — this is the
**lineage** so you can trace which prompt version produced which fix.

---

## 8 · Approve fixes & re-scan

In the UI:
1. **Review** the proposed fixes (diff viewer).
2. **Approve** the ones you want.
3. The graph resumes (`Command(resume=...)` is sent to LangGraph), the
   `applier_node` writes them to disk + commits.
4. The `evaluator_node` decides whether to re-scan and loop, or stop.

After approval, a new commit will land on a `raven/mitigation-...`
branch in the cloned working directory.

---

## 9 · Backend unit tests

```powershell
cd "C:\Users\SunilKumarPradhan\Desktop\Master Folder\RavenProject\raven-platform\backend"

# AGP unit tests
python -m pytest src/services/agents/agp/ -v

# Graph node tests (if present)
python -m pytest src/services/agents/nodes/ -v

# Full backend suite
python -m pytest -v --maxfail=5
```

---

## 10 · Smoke-test the AGP module manually

```python
# from raven-platform/backend
python -c "
from src.services.agents.agp.registry import ResourceRegistry
from src.services.agents.agp.protocol import ResourceType, InterfaceSpec
from src.services.agents.agp.evolution import EvolutionEngine, IterationMetrics, compute_metrics

reg = ResourceRegistry()
reg.clear()
res = reg.register(
    name='prompt:test',
    resource_type=ResourceType.PROMPT,
    payload={'system_prompt': 'You are a security fixer.', 'temperature': 0.15},
    interface_spec=InterfaceSpec(inputs=('vulns',), outputs=('fix',)),
)
print('Registered:', res.name, 'v', res.current_version, res.state.value)

engine = EvolutionEngine(registry=reg)
m = compute_metrics(proposed=[], rejected=[{'file':'x','status':'rejected'}], iteration=1, session_id='s1')
print('Metrics:', m.to_dict())
results = engine.evolve_underperforming(m, baseline_metrics=None, session_id='s1')
print('Evolution results:', results)
print(reg.summary())
print(engine.summary())
"
```

Expected output:

```
Registered: prompt:test v 1 active
Metrics: {'iteration': 1, 'total_proposed': 1, 'total_approved': 0, ...}
Evolution results: {'prompt:test': True}   # rule-based proposal applied
AGP Registry: 1 resources
  [prompt     ] prompt:test                    v2 (active) lineage=2
Evolution Engine: 1 cycles (1 committed, 0 rolled back)
```

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `ImportError: GraphMitigationOrchestrator` | Make sure `backend/src/services/agents/graph_orchestrator.py` exists (it should after the refactor) |
| `langgraph.checkpoint.postgres` import error | `pip install langgraph-checkpoint-postgres` |
| `langmem` not found | Optional — graph falls back to `InMemoryStore` automatically |
| WebSocket disconnects mid-iteration | The graph is sync; we run it in `run_in_executor`. If still disconnecting, lower `max_iterations` in the project config |
| AGP evolution never fires | Check logs — it only triggers when `fix_success_rate < 50%` *or* `avg_confidence < 0.5`. Use a weak/cheap model to force this |
| Stack-trace leaking in production | The demo error handler exposes stack traces — this is expected behaviour for the test target |

---

## What "good" looks like end-to-end

A successful run produces:

1. **Scan** — 30+ findings from the dummy-repo
2. **Mitigation iteration 1**
   - Context-gatherer pulls 5+ files for `/login`
   - 4 fixer sub-agents run in parallel via `Send()`
   - Peer reviewer flags low-quality fixes
   - Validator approves ~50–70% of fixes
   - **AGP SEPL** evolves prompt(s) at end of iteration
3. **User review** — UI pauses on `interrupt()`
4. **Apply** — git commit on a new branch
5. **Re-scan** — fewer findings (or evaluator marks remaining as unfixable)
6. **Checkpoint** — state + AGP lineage persisted to Postgres

Happy hunting.
