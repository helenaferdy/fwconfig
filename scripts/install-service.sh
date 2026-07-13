#!/usr/bin/env bash
set -euo pipefail

ROOT=/opt/fwmigrate
cd "$ROOT"

echo "==> Ensuring Python venv and dependencies"
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r backend/requirements.txt

echo "==> Building frontend (static export)"
cd frontend
npm install --silent
npm run build
cd "$ROOT"

echo "==> Installing systemd unit"
cp deploy/fwmigrate.service /etc/systemd/system/fwmigrate.service
systemctl daemon-reload
systemctl enable fwmigrate.service
systemctl restart fwmigrate.service

echo "==> Status"
systemctl --no-pager status fwmigrate.service || true
echo
echo "Service listening on http://0.0.0.0:8006"
echo "API docs: http://127.0.0.1:8006/api/docs"
