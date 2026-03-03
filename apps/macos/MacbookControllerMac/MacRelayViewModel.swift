import AppKit
import CryptoKit
import Foundation
import ScreenCaptureKit

private let rekeyIntervalSeconds: TimeInterval = 300
private let rekeyMessageLimit: Int = 300

@MainActor
final class MacRelayViewModel: ObservableObject {
    @Published var relayHTTPURL = "http://127.0.0.1:8787"
    @Published var relayWSURL = "ws://127.0.0.1:8787"
    @Published var deviceToken = "change-me"
    @Published var pairingCode = "-"
    @Published var status = "Idle"
    @Published var e2eFingerprint = "-"
    @Published var isFingerprintTrusted = false

    private var socketTask: URLSessionWebSocketTask?
    private var frameTask: Task<Void, Never>?
    private let session = URLSession(configuration: .default)
    private let frameProducer = ScreenFrameProducer()
    private let injector = CGEventInjector()

    private var e2eKey: SymmetricKey?
    private var pendingPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var keyActivatedAt: Date?
    private var outboundCountSinceKey = 0
    private var outboundSeq: Int64 = 0
    private var lastInboundSeq: Int64 = 0
    private var rekeyInFlight = false

    func startSession() async {
        stopSession()
        status = "Creating pairing code..."

        do {
            let code = try await createPairCode()
            pairingCode = code
            status = "Code \(code) created. Connecting..."
            try connectWebSocket(code: code)
            receiveLoop()
            startFrameLoop()
            status = "Connected. Waiting for iPhone secure handshake..."
        } catch {
            status = "Failed to start: \(error.localizedDescription)"
        }
    }

    func stopSession() {
        resetSessionCryptoState()
        frameTask?.cancel()
        frameTask = nil
        socketTask?.cancel(with: .normalClosure, reason: nil)
        socketTask = nil
        status = "Stopped"
    }

    func trustFingerprint() {
        guard e2eKey != nil else {
            status = "No E2E key established yet"
            return
        }
        isFingerprintTrusted = true
        status = "Fingerprint trusted. Secure control enabled."
    }

    func clearTrust() {
        isFingerprintTrusted = false
        status = "Fingerprint trust cleared"
    }

    private func resetSessionCryptoState() {
        e2eKey = nil
        pendingPrivateKey = nil
        keyActivatedAt = nil
        outboundCountSinceKey = 0
        outboundSeq = 0
        lastInboundSeq = 0
        rekeyInFlight = false
        isFingerprintTrusted = false
        e2eFingerprint = "-"
    }

    private func createPairCode() async throws -> String {
        guard let url = URL(string: relayHTTPURL + "/api/codes") else {
            throw URLError(.badURL)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.timeoutInterval = 10
        request.setValue("Bearer \(deviceToken)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, http.statusCode == 200 else {
            throw NSError(domain: "Relay", code: 1)
        }

        let payload = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        guard let code = payload?["code"] as? String else {
            throw NSError(domain: "Relay", code: 2)
        }
        return code
    }

    private func connectWebSocket(code: String) throws {
        let clean = relayWSURL.hasSuffix("/") ? String(relayWSURL.dropLast()) : relayWSURL
        guard let url = URL(string: "\(clean)/ws/mac/\(code)?token=\(deviceToken)") else {
            throw URLError(.badURL)
        }

        let task = session.webSocketTask(with: url)
        socketTask = task
        task.resume()
    }

    private func receiveLoop() {
        guard let task = socketTask else { return }

        task.receive { [weak self] result in
            Task { @MainActor in
                guard let self else { return }

                switch result {
                case .failure(let error):
                    self.status = "Socket receive error: \(error.localizedDescription)"
                case .success(let message):
                    if case .string(let text) = message,
                       let data = text.data(using: .utf8),
                       let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        self.handleIncomingMessage(obj)
                    }
                    self.receiveLoop()
                @unknown default:
                    self.receiveLoop()
                }
            }
        }
    }

    private func startFrameLoop() {
        frameTask?.cancel()
        frameTask = Task { [weak self] in
            guard let self else { return }

            while !Task.isCancelled {
                guard let socketTask = self.socketTask else {
                    try? await Task.sleep(nanoseconds: 450_000_000)
                    continue
                }

                if self.shouldRekeyNow() {
                    self.initiateKeyExchange(as: "mac")
                }

                guard let key = self.e2eKey, self.isFingerprintTrusted else {
                    try? await Task.sleep(nanoseconds: 450_000_000)
                    continue
                }

                do {
                    if var frame = try await self.frameProducer.makeFrameMessage() {
                        self.outboundSeq += 1
                        frame["seq"] = self.outboundSeq
                        frame["payload_type"] = "frame"

                        let encrypted = try CryptoEnvelope.encryptJSONObject(frame, using: key)
                        let outbound: [String: Any] = [
                            "type": "secure_frame",
                            "combined": encrypted,
                        ]
                        try await self.sendJSON(outbound, over: socketTask)
                        self.outboundCountSinceKey += 1
                    }
                } catch {
                    self.status = "Frame send error: \(error.localizedDescription)"
                }

                try? await Task.sleep(nanoseconds: 450_000_000)
            }
        }
    }

    private func shouldRekeyNow() -> Bool {
        guard e2eKey != nil else { return false }
        guard !rekeyInFlight else { return false }

        if outboundCountSinceKey >= rekeyMessageLimit {
            return true
        }

        if let keyActivatedAt,
           Date().timeIntervalSince(keyActivatedAt) >= rekeyIntervalSeconds {
            return true
        }

        return false
    }

    private func sendJSON(_ payload: [String: Any], over task: URLSessionWebSocketTask? = nil) async throws {
        let target = task ?? socketTask
        guard let target else { return }

        let data = try JSONSerialization.data(withJSONObject: payload)
        guard let text = String(data: data, encoding: .utf8) else {
            throw NSError(domain: "Relay", code: 10)
        }
        try await target.send(.string(text))
    }

    private func handleIncomingMessage(_ message: [String: Any]) {
        guard let type = message["type"] as? String else { return }

        switch type {
        case "status":
            if let text = message["message"] as? String {
                status = text
            }
        case "e2e_hello":
            handleE2EHello(message)
        case "e2e_ack":
            handleE2EAck(message)
        case "secure_event":
            handleSecureEvent(message)
        default:
            break
        }
    }

    private func initiateKeyExchange(as sender: String) {
        let localPrivate = Curve25519.KeyAgreement.PrivateKey()
        pendingPrivateKey = localPrivate
        rekeyInFlight = true

        let hello: [String: Any] = [
            "type": "e2e_hello",
            "from": sender,
            "pub": Data(localPrivate.publicKey.rawRepresentation).base64EncodedString(),
        ]

        Task {
            do {
                try await sendJSON(hello)
                status = "Sent E2E hello (\(sender))"
            } catch {
                status = "E2E hello failed: \(error.localizedDescription)"
                rekeyInFlight = false
            }
        }
    }

    private func activateKey(_ key: SymmetricKey) {
        e2eKey = key
        keyActivatedAt = Date()
        outboundCountSinceKey = 0
        outboundSeq = 0
        lastInboundSeq = 0
        rekeyInFlight = false
        isFingerprintTrusted = false
        e2eFingerprint = CryptoEnvelope.fingerprint(for: key)
        status = "New E2E key ready. Compare fingerprint and trust."
    }

    private func handleE2EHello(_ message: [String: Any]) {
        guard let peerPubB64 = message["pub"] as? String,
              let peerPubData = Data(base64Encoded: peerPubB64) else {
            status = "Invalid E2E hello payload"
            return
        }

        do {
            let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPubData)
            let localPrivate = Curve25519.KeyAgreement.PrivateKey()
            let sharedSecret = try localPrivate.sharedSecretFromKeyAgreement(with: peerPublicKey)
            let key = CryptoEnvelope.deriveSymmetricKey(from: sharedSecret)
            activateKey(key)

            let ack: [String: Any] = [
                "type": "e2e_ack",
                "from": "mac",
                "pub": Data(localPrivate.publicKey.rawRepresentation).base64EncodedString(),
            ]

            Task {
                do {
                    try await sendJSON(ack)
                    status = "E2E ack sent. Verify fingerprint."
                } catch {
                    status = "E2E ack failed: \(error.localizedDescription)"
                }
            }
        } catch {
            status = "E2E setup failed: \(error.localizedDescription)"
        }
    }

    private func handleE2EAck(_ message: [String: Any]) {
        guard let localPrivate = pendingPrivateKey else { return }
        guard let peerPubB64 = message["pub"] as? String,
              let peerPubData = Data(base64Encoded: peerPubB64) else {
            status = "Invalid E2E ack payload"
            return
        }

        do {
            let peerPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPubData)
            let sharedSecret = try localPrivate.sharedSecretFromKeyAgreement(with: peerPublicKey)
            let key = CryptoEnvelope.deriveSymmetricKey(from: sharedSecret)
            pendingPrivateKey = nil
            activateKey(key)
        } catch {
            status = "E2E ack processing failed: \(error.localizedDescription)"
        }
    }

    private func handleSecureEvent(_ message: [String: Any]) {
        guard let key = e2eKey else {
            status = "Ignored secure event: key not ready"
            return
        }
        guard isFingerprintTrusted else {
            status = "Trust fingerprint before accepting controls"
            return
        }
        guard let combined = message["combined"] as? String else {
            status = "Invalid secure event payload"
            return
        }

        do {
            var decrypted = try CryptoEnvelope.decryptJSONObject(combinedB64: combined, using: key)
            guard let seq = decrypted["seq"] as? Int64 ?? (decrypted["seq"] as? Int).map(Int64.init) else {
                status = "Secure event missing sequence"
                return
            }
            guard seq > lastInboundSeq else {
                status = "Replay detected: dropped stale event"
                return
            }
            lastInboundSeq = seq
            decrypted.removeValue(forKey: "seq")
            decrypted.removeValue(forKey: "payload_type")
            injector.apply(message: decrypted)
        } catch {
            status = "Secure event decrypt failed"
        }
    }
}

actor ScreenFrameProducer {
    private var contentFilter: SCContentFilter?
    private var width = 1280
    private var height = 720

    func makeFrameMessage(quality: CGFloat = 0.45) async throws -> [String: Any]? {
        let filter = try await getContentFilter()
        let config = SCStreamConfiguration()
        config.width = width
        config.height = height

        let cgImage = try await SCScreenshotManager.captureImage(contentFilter: filter, configuration: config)
        let bitmapRep = NSBitmapImageRep(cgImage: cgImage)

        guard let data = bitmapRep.representation(using: .jpeg, properties: [.compressionFactor: quality]) else {
            return nil
        }

        let b64 = data.base64EncodedString()
        return [
            "type": "frame",
            "width": width,
            "height": height,
            "image": "data:image/jpeg;base64,\(b64)",
        ]
    }

    private func getContentFilter() async throws -> SCContentFilter {
        if let contentFilter {
            return contentFilter
        }

        let shareableContent = try await SCShareableContent.excludingDesktopWindows(false, onScreenWindowsOnly: true)
        guard let display = shareableContent.displays.first else {
            throw NSError(domain: "ScreenCapture", code: 1)
        }

        width = Int(display.width)
        height = Int(display.height)

        let filter = SCContentFilter(display: display, excludingWindows: [])
        self.contentFilter = filter
        return filter
    }
}

enum CryptoEnvelope {
    private static let salt = Data("macbook-controller-salt-v1".utf8)
    private static let info = Data("macbook-controller-e2e-v1".utf8)

    static func deriveSymmetricKey(from sharedSecret: SharedSecret) -> SymmetricKey {
        sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: 32
        )
    }

    static func encryptJSONObject(_ object: [String: Any], using key: SymmetricKey) throws -> String {
        let plaintext = try JSONSerialization.data(withJSONObject: object)
        let sealed = try AES.GCM.seal(plaintext, using: key)
        guard let combined = sealed.combined else {
            throw NSError(domain: "Crypto", code: 1)
        }
        return combined.base64EncodedString()
    }

    static func decryptJSONObject(combinedB64: String, using key: SymmetricKey) throws -> [String: Any] {
        guard let combined = Data(base64Encoded: combinedB64) else {
            throw NSError(domain: "Crypto", code: 2)
        }
        let sealedBox = try AES.GCM.SealedBox(combined: combined)
        let plaintext = try AES.GCM.open(sealedBox, using: key)
        guard let object = try JSONSerialization.jsonObject(with: plaintext) as? [String: Any] else {
            throw NSError(domain: "Crypto", code: 3)
        }
        return object
    }

    static func fingerprint(for key: SymmetricKey) -> String {
        let keyBytes = key.withUnsafeBytes { Data($0) }
        let digest = SHA256.hash(data: keyBytes)
        let hex = digest.prefix(8).map { String(format: "%02X", $0) }
        return stride(from: 0, to: hex.count, by: 2)
            .map { idx in hex[idx..<min(idx + 2, hex.count)].joined(separator: "") }
            .joined(separator: "-")
    }
}

final class CGEventInjector {
    private let displayBounds = CGDisplayBounds(CGMainDisplayID())

    func apply(message: [String: Any]) {
        guard let type = message["type"] as? String else { return }

        switch type {
        case "move":
            mouseMove(message)
        case "click":
            mouseClick(message, count: 1)
        case "double_click":
            mouseClick(message, count: 2)
        case "scroll":
            scroll(message)
        case "key":
            keyPress(message)
        case "type_text":
            typeText(message)
        default:
            break
        }
    }

    private func point(from message: [String: Any]) -> CGPoint {
        let x = (message["x"] as? Double) ?? 0.5
        let y = (message["y"] as? Double) ?? 0.5
        return CGPoint(
            x: displayBounds.origin.x + displayBounds.width * x,
            y: displayBounds.origin.y + displayBounds.height * y
        )
    }

    private func mouseMove(_ message: [String: Any]) {
        let p = point(from: message)
        let move = CGEvent(mouseEventSource: nil, mouseType: .mouseMoved, mouseCursorPosition: p, mouseButton: .left)
        move?.post(tap: .cghidEventTap)
    }

    private func mouseClick(_ message: [String: Any], count: Int) {
        let p = point(from: message)
        let down = CGEvent(mouseEventSource: nil, mouseType: .leftMouseDown, mouseCursorPosition: p, mouseButton: .left)
        down?.setIntegerValueField(.mouseEventClickState, value: Int64(count))
        let up = CGEvent(mouseEventSource: nil, mouseType: .leftMouseUp, mouseCursorPosition: p, mouseButton: .left)
        up?.setIntegerValueField(.mouseEventClickState, value: Int64(count))

        down?.post(tap: .cghidEventTap)
        up?.post(tap: .cghidEventTap)
        if count == 2 {
            down?.post(tap: .cghidEventTap)
            up?.post(tap: .cghidEventTap)
        }
    }

    private func scroll(_ message: [String: Any]) {
        let amount = (message["amount"] as? Int) ?? 0
        let event = CGEvent(scrollWheelEvent2Source: nil, units: .pixel, wheelCount: 1, wheel1: Int32(amount), wheel2: 0, wheel3: 0)
        event?.post(tap: .cghidEventTap)
    }

    private func keyPress(_ message: [String: Any]) {
        guard let key = message["key"] as? String else { return }
        let keyCode = keyCodeFor(key)
        let down = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: true)
        let up = CGEvent(keyboardEventSource: nil, virtualKey: keyCode, keyDown: false)
        down?.post(tap: .cghidEventTap)
        up?.post(tap: .cghidEventTap)
    }

    private func typeText(_ message: [String: Any]) {
        guard let text = message["text"] as? String else { return }
        let chars = Array(text.utf16)
        guard !chars.isEmpty else { return }

        let down = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: true)
        down?.keyboardSetUnicodeString(stringLength: chars.count, unicodeString: chars)
        down?.post(tap: .cghidEventTap)

        let up = CGEvent(keyboardEventSource: nil, virtualKey: 0, keyDown: false)
        up?.keyboardSetUnicodeString(stringLength: chars.count, unicodeString: chars)
        up?.post(tap: .cghidEventTap)
    }

    private func keyCodeFor(_ key: String) -> CGKeyCode {
        switch key.lowercased() {
        case "esc", "escape": return 53
        case "return", "enter": return 36
        case "space": return 49
        case "tab": return 48
        case "delete", "backspace": return 51
        case "up": return 126
        case "down": return 125
        case "left": return 123
        case "right": return 124
        default: return 53
        }
    }
}
