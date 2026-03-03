# Mac iPhone Remote Control (Standalone Project)

This is a separate project from your AI assistant and math app.

## What this MVP does
- Streams your Mac screen to an iPhone web controller.
- Sends click, move, scroll, key, and typed-text events from iPhone to Mac.
- Uses a relay backend so it works over the internet when deployed.
- Uses short-lived 6-digit pairing codes.

## Project layout
- `relay/`: FastAPI relay + pairing code API + WebSocket bridge
- `mac_agent/`: Python agent that captures frames and executes remote inputs on macOS
- `controller/`: iPhone-friendly web UI (open in Safari)

## 1) Run relay server
```bash
cd relay
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export MAC_DEVICE_TOKEN='replace-with-long-random-token'
uvicorn relay_server:app --host 0.0.0.0 --port 8787
```

## 2) Run Mac agent
```bash
cd mac_agent
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `.env`:
```env
RELAY_HTTP_URL=http://YOUR_RELAY_HOST:8787
RELAY_WS_URL=ws://YOUR_RELAY_HOST:8787
MAC_DEVICE_TOKEN=replace-with-long-random-token
```

Start:
```bash
python agent.py
```

The agent prints a 6-digit code. Use it from iPhone.

## 3) Open controller on iPhone
- Host `controller/index.html` anywhere static (or open locally for testing).
- Enter `ws://YOUR_RELAY_HOST:8787` and the 6-digit code.

## macOS permissions required
- System Settings -> Privacy & Security -> Accessibility: allow terminal/python app
- Screen Recording: allow terminal/python app

## Internet deployment notes
- Put relay behind HTTPS/WSS (reverse proxy + TLS)
- Use strong random `MAC_DEVICE_TOKEN`
- Restrict CORS/origins in `relay_server.py` before production
- Add rate limiting and audit logs before full production usage
