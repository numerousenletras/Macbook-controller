import AppKit
import CryptoKit
import Foundation
import ScreenCaptureKit

@MainActor
final class MacRelayViewModel: ObservableObject {
    @Published var relayHTTPURL = "http://127.0.0.1:8787"
    @Published var relayWSURL = "ws://127.0.0.1:8787"
    @Published var deviceToken = "change-me"
    @Published var pairingCode = "-"
    @Published var status = "Idle"

    private var socketTask: URLSessionWebSocketTask?
    private var frameTask: Task<Void, Never>?
    private let session = URLSession(configuration: .default)
    private let frameProducer = ScreenFrameProducer()
    private let injector = CGEventInjector()

    private var e2eKey: SymmetricKey?

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
        e2eKey = nil
        frameTask?.cancel()
        frameTask = nil
        socketTask?.cancel(with: .normalClosure, reason: nil)
        socketTask = nil
        status = "Stopped"
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

                guard let key = self.e2eKey else {
                    try? await Task.sleep(nanoseconds: 450_000_000)
                    continue
                }

                do {
                    if let frame = try await self.frameProducer.makeFrameMessage() {
                        let encrypted = try CryptoEnvelope.encryptJSONObject(frame, using: key)
                        let outbound: [String: Any] = [
                            "type": "secure_frame",
                            "combined": encrypted,
                        ]
                        try await self.sendJSON(outbound, over: socketTask)
                    }
                } catch {
                    self.status = "Frame send error: \(error.localizedDescription)"
                }

                try? await Task.sleep(nanoseconds: 450_000_000)
            }
        }
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
        case "secure_event":
            handleSecureEvent(message)
        default:
            break
        }
    }

    private func handleE2EHello(_ message: [String: Any]) {
        guard let phonePubB64 = message["phone_pub"] as? String,
              let phonePubData = Data(base64Encoded: phonePubB64) else {
            status = "Invalid E2E hello payload"
            return
        }

        do {
            let phonePublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: phonePubData)
            let macPrivateKey = Curve25519.KeyAgreement.PrivateKey()
            let sharedSecret = try macPrivateKey.sharedSecretFromKeyAgreement(with: phonePublicKey)
            let key = CryptoEnvelope.deriveSymmetricKey(from: sharedSecret)
            e2eKey = key

            let ack: [String: Any] = [
                "type": "e2e_ack",
                "mac_pub": Data(macPrivateKey.publicKey.rawRepresentation).base64EncodedString(),
            ]

            Task {
                do {
                    try await sendJSON(ack)
                    status = "Secure E2E session established"
                } catch {
                    status = "E2E ack failed: \(error.localizedDescription)"
                }
            }
        } catch {
            status = "E2E setup failed: \(error.localizedDescription)"
        }
    }

    private func handleSecureEvent(_ message: [String: Any]) {
        guard let key = e2eKey else {
            status = "Ignored insecure event: E2E not ready"
            return
        }

        guard let combined = message["combined"] as? String else {
            status = "Invalid secure event payload"
            return
        }

        do {
            let decrypted = try CryptoEnvelope.decryptJSONObject(combinedB64: combined, using: key)
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
