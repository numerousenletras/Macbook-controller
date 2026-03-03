# Native Apps (iOS + macOS)

This repo includes native SwiftUI sources for both apps:
- `apps/macos/MacbookControllerMac`: macOS agent app (creates pair code, streams screen, executes remote input)
- `apps/ios/MacbookControlleriOS`: iPhone controller app (connects by pair code, renders frames, sends control events)

## End-to-end encryption
The native apps use an app-layer E2E channel over WSS:
1. iOS sends `e2e_hello` with an ephemeral Curve25519 public key.
2. macOS responds with `e2e_ack` and its ephemeral Curve25519 public key.
3. Both derive a shared key using HKDF-SHA256.
4. Frames and events use AES-GCM encrypted envelopes (`secure_frame`, `secure_event`).

The relay server only sees ciphertext for those payloads.

## Build with XcodeGen

1. Install XcodeGen:
```bash
brew install xcodegen
```

2. Generate the Xcode project:
```bash
cd apps
xcodegen generate
```

3. Open `MacbookController.xcodeproj` in Xcode.

4. Build and run:
- `MacbookControllerMac` on your Mac
- `MacbookControlleriOS` on your iPhone

## macOS permissions
On first run, grant the macOS app:
- Screen Recording
- Accessibility

Without these permissions, stream/control features will not work.
