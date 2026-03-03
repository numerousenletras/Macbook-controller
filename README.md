# Macbook Controller

Control your Mac from your iPhone over the internet with a hardened relay and native apps.

## What is in this repo
- `relay/` FastAPI relay server (pair codes + WebSocket bridge + hardening)
- `apps/macos/MacbookControllerMac` native macOS agent app
- `apps/ios/MacbookControlleriOS` native iPhone controller app
- `deploy/` HTTPS/WSS deployment files (Caddy + docker compose)
- `controller/` fallback web controller (non-native)

## Security model
- TLS transport via HTTPS/WSS
- App-layer E2E encryption in native apps (Curve25519 + HKDF + AES-GCM)
- Fingerprint trust confirmation required before stream/control
- Replay protection with monotonic encrypted sequence counters
- Automatic rekey every 5 minutes or 300 encrypted messages

## 1) Run the relay server (local test)
```bash
cd relay
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Edit `relay/.env`:
```env
MAC_DEVICE_TOKEN=replace-with-long-random-token
PAIR_CODE_TTL_SECONDS=300
ALLOWED_ORIGINS=
REQUIRE_HTTPS=false
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_CREATE_CODE=15
RATE_LIMIT_CHECK_CODE=120
```

Start relay:
```bash
uvicorn relay_server:app --host 0.0.0.0 --port 8787
```

## 2) Run native apps in Xcode
You now have a checked-in project file, so you can open directly:
- `apps/MacbookController.xcodeproj`

Optional regeneration (if project spec changes):
```bash
brew install xcodegen
cd apps
xcodegen generate
```

In Xcode:
1. Run target `MacbookControllerMac` on your Mac.
2. Run target `MacbookControlleriOS` on your iPhone.
3. Set Signing Team for both targets if prompted.

## 3) First-time permissions on macOS
Grant the macOS app:
- System Settings -> Privacy & Security -> Screen Recording
- System Settings -> Privacy & Security -> Accessibility

Then fully quit and relaunch the Mac app.

## 4) Pair and test
1. In Mac app, enter relay URLs and token, then click **Start Session**.
2. Mac app shows a 6-digit code and E2E fingerprint.
3. In iPhone app, enter relay WS URL and code, then connect.
4. Compare fingerprints on both devices and press **Trust** on both.
5. Stream + controls should go live.

## 5) Production deploy (HTTPS/WSS)
Use `deploy/Caddyfile` + `deploy/docker-compose.yml`.

Edit domains in `deploy/Caddyfile`:
- `relay.yourdomain.com`
- `controller.yourdomain.com`

Set relay env for production:
```env
REQUIRE_HTTPS=true
ALLOWED_ORIGINS=https://controller.yourdomain.com
```

Then:
```bash
cd deploy
docker compose up -d
```

## Troubleshooting
- iPhone app connects but no stream: fingerprint likely not trusted yet on one side.
- No controls: macOS Accessibility permission missing.
- Blank frames: macOS Screen Recording permission missing.
- WebSocket fails remotely: check DNS/TLS and use `wss://` URL.
