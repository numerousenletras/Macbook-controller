# Native Apps (iOS + macOS)

## Paths
- `apps/macos/MacbookControllerMac` (macOS agent)
- `apps/ios/MacbookControlleriOS` (iPhone controller)
- `apps/MacbookController.xcodeproj` (ready to open)

## Build/run
1. Open `apps/MacbookController.xcodeproj` in Xcode.
2. Set Signing Team for both targets if prompted.
3. Run `MacbookControllerMac` on Mac.
4. Run `MacbookControlleriOS` on iPhone.

Optional: regenerate project from `apps/project.yml`:
```bash
brew install xcodegen
cd apps
xcodegen generate
```

## E2E protocol
1. iOS sends `e2e_hello` with ephemeral Curve25519 public key.
2. macOS responds with `e2e_ack` and its ephemeral key.
3. Both derive the same session key via HKDF-SHA256.
4. Frames/events are sent as AES-GCM encrypted envelopes.

## Safety controls
- Fingerprint trust gate must be confirmed on both devices.
- Replay defense drops stale sequence numbers.
- Session rekeys automatically every 5 minutes or 300 encrypted messages.

## macOS permissions
- Screen Recording
- Accessibility

Without both permissions, stream/control will not work.
