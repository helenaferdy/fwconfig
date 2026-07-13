# FW Config Analyzer

Deterministic firewall **configuration analysis** and human-readable documentation, with an optional AI consultant for Q&A over the parsed config.

**Product name:** FW Config Analyzer  
**Repo:** [helenaferdy/fwconfig](https://github.com/helenaferdy/fwconfig)  
**Runtime path (this deploy):** `/opt/fwmigrate` · systemd unit `fwmigrate` · port **8006**

## Analysis path

```
Source config → Vendor parser → Structured model → Template summaries → Human-readable overview
```

- **Parsing & summaries are never AI-driven** (deterministic parsers + formatters).
- **AI (OpenCode / DeepSeek)** explains, searches usage (e.g. “what policy uses Sarulla-Antivirus”), and posts an intro after analysis. It only uses session digests/lookups — it does not invent objects.

## Stack

| Layer    | Technology                          |
|----------|-------------------------------------|
| Backend  | Python 3.12, FastAPI, Pydantic      |
| Frontend | React, Next.js 14 (static export), Tailwind |
| Deploy   | Linux systemd, port **8006**        |
| Sessions | Disk-backed JSON under `data/sessions/` |
| AI       | OpenCode zen API · `deepseek-v4-flash` |

## Supported input vendors

- Fortigate (deepest coverage: interfaces, addresses, services, policies + UTM profiles, routes, VPN, users, …)
- Palo Alto
- Check Point
- Cisco FTD

No target conversion — output is **human-readable analysis** for migration review, not a new vendor config.

## Project layout

```
/opt/fwmigrate/          # or your clone of fwconfig
  backend/
    api/           # FastAPI routes
    session/       # Disk session store
    parser/        # Per-vendor parsers (Fortigate is thorough)
    model/         # Vendor-neutral objects + taxonomy
    summary/       # Template formatters + enrich
    pipeline/      # Parse / analyze orchestration
    ai/            # OpenCode / DeepSeek client (intro, chat, usage lookup)
    utils/
    main.py
  frontend/        # Next.js app → static export to frontend/out
  data/sessions/   # Runtime session data (gitignored)
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

- App: http://127.0.0.1:8006  
- API docs: http://127.0.0.1:8006/api/docs  

## Environment

Configure via `.env` (gitignored) at project root or `backend/.env`:

| Variable | Purpose |
|----------|---------|
| `OPENCODE_API_KEY` | OpenCode API key (required for AI chat/intro) |
| `OPENCODE_BASE_URL` | Default `https://opencode.ai/zen/go/v1` |
| `OPENCODE_MODEL` | Default `deepseek-v4-flash` |
| `AI_ENABLED` | `true` / `false` |
| `PORT` | Default `8006` |

## Service management

```bash
systemctl status fwmigrate
systemctl restart fwmigrate
journalctl -u fwmigrate -f
```

After frontend changes:

```bash
cd /opt/fwmigrate/frontend && npm run build
systemctl restart fwmigrate
```

## API overview

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/sessions/upload` | Upload config; auto-parse + summarize (AI intro async) |
| GET | `/api/sessions/{id}` | Session state (poll for intro chat messages) |
| POST | `/api/sessions/{id}/analyze` | Refresh human-readable summary |
| POST | `/api/sessions/{id}/chat` | AI consultant |
| GET | `/api/vendors` | List input vendors |
| GET | `/api/health` | Health check |
| GET | `/api/taxonomy` | Explorer category tree |

## UI

Three-pane dashboard (default ratio **3.5 : 4.5 : 3**, resizable):

1. **Left** – Upload (full drop zone clickable) → section list + raw CLI  
2. **Center** – Human-readable overview / section detail (All · Refresh)  
3. **Right** – Process log + AI chat (intro summary after parse; tall ask box)  

Header: **FW Config Analyzer | vendor · filename · object count**

### AI behavior (high level)

- After parse, left/center return immediately; intro is generated in the background and polled into chat.
- Intro is a real config summary (hostname, counts, warnings), ending with “Ask me questions.”
- Usage questions (e.g. which policies use a profile) use local search over policy UTM fields / raw config.

## Design principles

- Parsers are deterministic (no AI)  
- Summaries are template-driven (no AI)  
- AI only explains / searches session data  
- Sessions are fully isolated on disk  
- Secrets (`.env`) are never committed  

## License / notes

Internal analysis tooling. Keep API keys in `.env` only.
