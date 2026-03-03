# Macbook Controller

Standalone project for controlling your Mac from your iPhone over the internet.

## Included
- Hardened relay backend (`relay/`) with:
  - short-lived pair codes
  - token-authenticated Mac registration
  - optional HTTPS enforcement
  - origin allowlist
  - per-IP rate limits
  - security response headers
- Native macOS app source (`apps/macos/MacbookControllerMac`)
- Native iOS app source (`apps/ios/MacbookControlleriOS`)
- Web controller fallback (`controller/`)
- HTTPS/WSS deployment configs (`deploy/`)

## Architecture
1. macOS app creates pair code via relay API.
2. macOS app and iOS app connect to relay WebSockets.
3. iOS app sends `e2e_hello` with ephemeral key.
4. macOS app replies with `e2e_ack` and both derive a shared AES-GCM key.
5. Frames and control events are sent as encrypted envelopes (`secure_frame`, `secure_event`).
6. Relay only routes ciphertext and cannot read screen or control payloads.

## Relay setup (production)
```bash
cd relay
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

Update `relay/.env`:
```env
MAC_DEVICE_TOKEN=replace-with-long-random-token
PAIR_CODE_TTL_SECONDS=300
ALLOWED_ORIGINS=https://controller.yourdomain.com
REQUIRE_HTTPS=true
RATE_LIMIT_WINDOW_SECONDS=60
RATE_LIMIT_CREATE_CODE=15
RATE_LIMIT_CHECK_CODE=120
```

Run relay:
```bash
uvicorn relay_server:app --host 0.0.0.0 --port 8787
```

## HTTPS/WSS deployment
Use `deploy/Caddyfile` and `deploy/docker-compose.yml`.

Edit domains in `deploy/Caddyfile`:
- `relay.yourdomain.com`
- `controller.yourdomain.com`

Start stack:
```bash
cd deploy
docker compose up -d
```

This gives:
- HTTPS endpoint for API (`https://relay.yourdomain.com`)
- WSS endpoint for sockets (`wss://relay.yourdomain.com`)
- static hosting for the fallback web controller (`https://controller.yourdomain.com`)

## Native app build
See [apps/README.md](apps/README.md).

Quick start:
```bash
brew install xcodegen
cd apps
xcodegen generate
```

Then open `MacbookController.xcodeproj` in Xcode and run:
- `MacbookControllerMac` on Mac
- `MacbookControlleriOS` on iPhone

## macOS permissions
For the macOS app/agent to work:
- System Settings -> Privacy & Security -> Screen Recording
- System Settings -> Privacy & Security -> Accessibility

## Security checklist
- Use a long random `MAC_DEVICE_TOKEN`
- Keep `REQUIRE_HTTPS=true` in production
- Set explicit `ALLOWED_ORIGINS`
- Run relay behind Caddy/Nginx with TLS
- Use the native iOS/macOS apps for E2E encrypted control sessions
- Put relay behind firewall and monitor logs
