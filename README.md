# FW Config Analyzer

Deterministic firewall **configuration analysis** and human-readable documentation, with an optional AI consultant for Q&A over the parsed config.

**Product name:** FW Config Analyzer  
**Repo:** [helenaferdy/fwconfig](https://github.com/helenaferdy/fwconfig)  
**Runtime path (this deploy):** `/opt/fwconfig` · systemd unit `fwconfig` · port **8006**

## Analysis path

```
Source config → Vendor parser → Structured model → Template summaries → Human-readable overview
```

- **Parsing & summaries are never AI-driven** (deterministic parsers + formatters).
- **AI (OpenCode / DeepSeek)** explains, searches usage (e.g. “what policy uses Sarulla-Antivirus”), posts an intro after analysis, and supports **compare-mode** dual digests. It only uses session digests/lookups — it does not invent objects.

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
/opt/fwconfig/          # or your clone of fwconfig
  backend/
    api/           # FastAPI routes
    session/       # Disk session store
    parser/        # Per-vendor parsers (Fortigate is thorough)
    model/         # Vendor-neutral objects + taxonomy
    summary/       # Template formatters + enrich
    pipeline/      # Parse / analyze orchestration
    ai/            # OpenCode / DeepSeek client (intro, compare intro, chat, usage lookup)
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
sudo bash /opt/fwconfig/scripts/install-service.sh

# Or run manually
source /opt/fwconfig/.venv/bin/activate
cd /opt/fwconfig/backend
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
systemctl status fwconfig
systemctl restart fwconfig
journalctl -u fwconfig -f
```

After frontend changes:

```bash
cd /opt/fwconfig/frontend && npm run build
systemctl restart fwconfig
```

## API overview

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/sessions/upload` | Upload config; auto-parse + summarize (AI intro async) |
| GET | `/api/sessions/{id}` | Session state (poll for intro / compare-intro chat messages) |
| POST | `/api/sessions/{id}/analyze` | Refresh human-readable summary |
| POST | `/api/sessions/{id}/chat` | AI consultant (optional `compare_session_id` for dual digests) |
| POST | `/api/sessions/{id}/compare-intro` | Schedule async compare-mode intro when config B is loaded |
| GET | `/api/vendors` | List input vendors |
| GET | `/api/health` | Health check |
| GET | `/api/taxonomy` | Explorer category tree |

## UI

Three-pane dashboard (default ratio **3.5 : 4.5 : 3**, resizable):

1. **Left** – Raw configuration for the selected section/object  
2. **Center** – Human-readable overview / section table (All · Refresh on primary)  
3. **Right** – Unified section boxes (top) + AI chat (bottom)  

Header: **FW Config Analyzer | vendor · filename** · **compare** / **exit compare** · **new**

### Compare mode

- Click **compare** next to the config name (requires primary config **A**).
- Left + mid split **horizontally**: **A on top**, **B on bottom**. Right pane stays the same (section picker + chat).
- Load **B** from the bottom-left pane only: 4-vendor upload + history dropdown (any platform).
- Section picker is the **union** of A and B taxonomy leaves; one selection drives all four panes.
- **Green** mid-pane rows / section boxes = object or section exists on **both** configs.
- **Purple** = selected row; selection uses the same match keys as compare (e.g. IPv4 without mask, destination+gateway for routes, policy names with `_`/`-` as spaces).
- Chat stays on session **A**; when B is loaded the AI receives digests for both configs and posts an async compare intro.

### AI behavior (high level)

- After parse, left/center return immediately; intro is generated in the background and polled into chat.
- Intro is a short config summary (vendor, hostname, object count), ending with an invite to ask questions.
- When config B is loaded in compare mode, a **compare intro** is scheduled async (`POST …/compare-intro`) and polled into chat.
- In compare mode, chat requests include `compare_session_id` so the model sees **DIGEST_A** and **DIGEST_B**.
- Usage questions (e.g. which policies use a profile) use local search over policy UTM fields / raw config (both sides when comparing).

### Browser history

- Recent runs are stored in **localStorage** (this browser only; max 10).
- Click the config name in the header to reopen a prior run (server session must still exist).

## Design principles

- Parsers are deterministic (no AI)  
- Summaries are template-driven (no AI)  
- AI only explains / searches session data  
- Sessions are fully isolated on disk  
- Secrets (`.env`) are never committed  

## License / notes

Internal analysis tooling. Keep API keys in `.env` only.
