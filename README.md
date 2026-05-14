# Multi-Agent Security (Hackathon MVP)

Minimal end-to-end autonomous dependency vulnerability remediation workflow.

## What it does

- Receives a GitHub **push** webhook
- Clones the pushed repo into `sandbox/repo_clones/`
- Runs `npm audit --json`
- Normalizes findings into an analysis object
- Asks IBM BOB (optional) for a patched `package.json` dependency snippet
- Applies the dependency version upgrade automatically
- Re-runs `npm audit` to validate the fix
- Writes a remediation report into `results/`
- Optionally creates a GitHub Pull Request (if `GITHUB_TOKEN` is set)

## Project structure

Matches the structure required in the prompt.

## Setup

### Prereqs

- Python 3.10+
- Node.js + npm available on PATH
- Git available on PATH

### Python deps

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Environment variables (.env)

Create a `.env` file in the repo root:

```env
# Optional but recommended: verify webhook signatures
GITHUB_WEBHOOK_SECRET=your_webhook_secret

# Optional: enables cloning private repos and PR creation
GITHUB_TOKEN=ghp_...
GITHUB_BASE_BRANCH=main

# Required for strict LLM remediation (OpenAI)
OPENAI_API_KEY=sk-...
# Optional
OPENAI_MODEL=gpt-4o-mini
```

## Run the orchestrator

```bash
uvicorn orchestrator.main:app --reload --port 8000
```

Health check:

```bash
curl -s http://localhost:8000/health
```

## GitHub webhook setup (push)

1. In GitHub repo settings → Webhooks → Add webhook
2. Payload URL: `http://<your-public-url>/webhook/github`
   - For local demo, use ngrok/cloudflared to expose port 8000.
3. Content type: `application/json`
4. Secret: set to match `GITHUB_WEBHOOK_SECRET`
5. Events: **Just the push event**

## Demo repository

Use this repo with the vulnerable axios version:
- https://github.com/kim815/vulnerable-repo

## Local demo (no webhook)

You can invoke the workflow directly by importing `run_workflow()` from `orchestrator/workflow.py`.

## Expected logs

You should see log lines for:
- cloning
- npm install
- npm audit parsing
- remediation attempt(s)
- validation
- report path

## Notes

- If IBM BOB isn’t configured, the remediation agent applies the `recommended_version` derived from npm audit.
- For a hackathon MVP, we delete `package-lock.json` to force a clean lockfile after remediation.
