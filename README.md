# Firewall Configuration Analysis Platform

Deterministic, explainable firewall configuration analysis and human-readable documentation.

**Analysis path (never AI-driven for parsing/summary):**

```
Source Configuration → Vendor Parser → Structured Model → Template Summaries → Human-Readable Overview
```

AI (OpenCode / DeepSeek-V4-Flash) is used only as a migration consultant: explain, review, highlight, advise.

## Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Backend  | Python 3.12, FastAPI, Pydantic      |
| Frontend | React, Next.js 14, TailwindCSS      |
| Deploy   | Linux systemd service, port **8006**|
| Sessions | Disk-backed JSON (`data/sessions/`) |

## Supported input vendors

- Fortigate
- Palo Alto
- Check Point
- Cisco FTD

No target vendor selection — the product produces **human-readable configuration summaries** for manual migration prep.

Deep parsing is strongest for Fortigate (interfaces, addresses, services, policies, routes). Other vendors ship with detection + section categorization stubs ready for expansion.

## Project layout

```
/opt/fwmigrate/
  backend/
    api/           # FastAPI routes
    session/       # Disk session store
    parser/        # Per-vendor parsers
    model/         # Vendor-neutral objects + dependency graph
    generator/     # Per-vendor generators
    validator/     # Post-parse / post-generate checks
    pipeline/      # Orchestration
    ai/            # OpenCode assistant client
    utils/
    main.py
  frontend/        # Next.js app (static export → frontend/out)
  data/sessions/   # Runtime session data
  deploy/          # systemd unit
  samples/         # Sample configs
  scripts/
```

## Quick start

```bash
# Install deps, build UI, install & start systemd service
sudo bash /opt/fwmigrate/scripts/install-service.sh

# Or run manually
source /opt/fwmigrate/.venv/bin/activate
cd /opt/fwmigrate/backend
uvicorn main:app --host 0.0.0.0 --port 8006
```

Open: http://127.0.0.1:8006  
API docs: http://127.0.0.1:8006/api/docs

## Environment

See `.env`:

- `OPENCODE_API_KEY` – OpenCode API key  
- `OPENCODE_MODEL=deepseek-v4-flash`  
- `PORT=8006`

## Service management

```bash
systemctl status fwmigrate
systemctl restart fwmigrate
journalctl -u fwmigrate -f
```

## API overview

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/sessions/upload` | Upload config, auto-parse + summarize |
| GET | `/api/sessions/{id}` | Session state |
| POST | `/api/sessions/{id}/analyze` | Refresh human-readable summary |
| POST | `/api/sessions/{id}/chat` | AI consultant |
| GET | `/api/vendors` | List input vendors |
| GET | `/api/health` | Health check |

## UI

Fixed three-pane dashboard (≈ **4 : 4 : 2**, resizable):

1. **Left** – Upload → Source explorer (raw CLI + parsed properties)  
2. **Center** – Human-readable configuration summary by section  
3. **Right** – Analysis log + AI consultant chat  

Selecting a source section scrolls the matching summary section.

## Design principles

- Parsers are deterministic (no AI)  
- Summaries are template-driven (no AI)  
- AI only explains / reviews session data  
- Sessions are fully isolated  
- Dependency graph powers unused-object and impact questions  
