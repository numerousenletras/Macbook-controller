import CryptoKit
import Foundation
import SwiftUI
import UIKit

private let rekeyIntervalSeconds: TimeInterval = 300
private let rekeyMessageLimit: Int = 300

@MainActor
final class IOSRelayViewModel: ObservableObject {
    @Published var relayWSURL = "ws://127.0.0.1:8787"
    @Published var code = ""
    @Published var status = "Idle"
    @Published var frameImage: UIImage?
    @Published var textToSend = ""
    @Published var e2eFingerprint = "-"
    @Published var isFingerprintTrusted = false

    private let session = URLSession(configuration: .default)
    private var socketTask: URLSessionWebSocketTask?

    private var pendingPrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var e2eKey: SymmetricKey?
    private var keyActivatedAt: Date?
    private var outboundCountSinceKey = 0
    private var outboundSeq: Int64 = 0
    private var lastInboundSeq: Int64 = 0
    private var rekeyInFlight = false

    func connect() {
        disconnect()

        let trimmedCode = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmedCode.count == 6 else {
            status = "Enter the 6-digit pairing code"
            return
        }

        let base = relayWSURL.hasSuffix("/") ? String(relayWSURL.dropLast()) : relayWSURL
        guard let url = URL(string: "\(base)/ws/phone/\(trimmedCode)") else {
            status = "Invalid relay URL"
            return
        }

        let task = session.webSocketTask(with: url)
        socketTask = task
        task.resume()
        status = "Connected. Starting secure handshake..."
        initiateKeyExchange(as: "ios")
        receiveLoop()
    }

    func disconnect() {
        resetSessionCryptoState()
        socketTask?.cancel(with: .normalClosure, reason: nil)
        socketTask = nil
        status = "Disconnected"
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

    func sendClick(x: CGFloat, y: CGFloat) {
        sendSecure(["type": "click", "x": x, "y": y, "button": "left"])
    }

    func sendScroll(_ amount: Int) {
        sendSecure(["type": "scroll", "amount": amount])
    }

    func sendKey(_ key: String) {
        sendSecure(["type": "key", "key": key])
    }

    func sendText() {
        let text = textToSend
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        sendSecure(["type": "type_text", "text": text])
        textToSend = ""
    }

    private func resetSessionCryptoState() {
        pendingPrivateKey = nil
        e2eKey = nil
        keyActivatedAt = nil
        outboundCountSinceKey = 0
        outboundSeq = 0
        lastInboundSeq = 0
        rekeyInFlight = false
        e2eFingerprint = "-"
        isFingerprintTrusted = false
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

    private func initiateKeyExchange(as sender: String) {
        let localPrivate = Curve25519.KeyAgreement.PrivateKey()
        pendingPrivateKey = localPrivate
        rekeyInFlight = true

        let hello: [String: Any] = [
            "type": "e2e_hello",
            "from": sender,
            "pub": Data(localPrivate.publicKey.rawRepresentation).base64EncodedString(),
        ]
        sendRaw(hello)
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

    private func sendSecure(_ payload: [String: Any]) {
        if shouldRekeyNow() {
            initiateKeyExchange(as: "ios")
        }

        guard let key = e2eKey else {
            status = "E2E not ready yet"
            return
        }
        guard isFingerprintTrusted else {
            status = "Trust fingerprint before sending controls"
            return
        }

        do {
            var enriched = payload
            outboundSeq += 1
            enriched["seq"] = outboundSeq
            enriched["payload_type"] = "event"
            let encrypted = try CryptoEnvelope.encryptJSONObject(enriched, using: key)
            sendRaw(["type": "secure_event", "combined": encrypted])
            outboundCountSinceKey += 1
        } catch {
            status = "Encrypt failed"
        }
    }

    private func sendRaw(_ payload: [String: Any]) {
        guard let task = socketTask else { return }
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let text = String(data: data, encoding: .utf8) else { return }

        task.send(.string(text)) { [weak self] error in
            Task { @MainActor in
                if let error {
                    self?.status = "Send failed: \(error.localizedDescription)"
                    self?.rekeyInFlight = false
                }
            }
        }
    }

    private func receiveLoop() {
        guard let task = socketTask else { return }

        task.receive { [weak self] result in
            Task { @MainActor in
                guard let self else { return }

                switch result {
                case .failure(let error):
                    self.status = "Socket error: \(error.localizedDescription)"
                case .success(let message):
                    if case .string(let text) = message,
                       let data = text.data(using: .utf8),
                       let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
                        self.processMessage(obj)
                    }
                    self.receiveLoop()
                @unknown default:
                    self.receiveLoop()
                }
            }
        }
    }

    private func processMessage(_ obj: [String: Any]) {
        guard let type = obj["type"] as? String else { return }

        switch type {
        case "status":
            if let message = obj["message"] as? String {
                status = message
            }
        case "e2e_hello":
            handleE2EHello(obj)
        case "e2e_ack":
            handleE2EAck(obj)
        case "secure_frame":
            handleSecureFrame(obj)
        default:
            break
        }
    }

    private func handleE2EHello(_ obj: [String: Any]) {
        guard let peerPubB64 = obj["pub"] as? String,
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
                "from": "ios",
                "pub": Data(localPrivate.publicKey.rawRepresentation).base64EncodedString(),
            ]
            sendRaw(ack)
        } catch {
            status = "E2E setup failed: \(error.localizedDescription)"
        }
    }

    private func handleE2EAck(_ obj: [String: Any]) {
        guard let localPrivate = pendingPrivateKey else { return }
        guard let peerPubB64 = obj["pub"] as? String,
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

    private func handleSecureFrame(_ obj: [String: Any]) {
        guard let key = e2eKey else {
            status = "Received secure frame before key"
            return
        }
        guard isFingerprintTrusted else {
            status = "Trust fingerprint before viewing stream"
            return
        }
        guard let combined = obj["combined"] as? String else {
            status = "Invalid secure frame payload"
            return
        }

        do {
            let decrypted = try CryptoEnvelope.decryptJSONObject(combinedB64: combined, using: key)
            guard let seq = decrypted["seq"] as? Int64 ?? (decrypted["seq"] as? Int).map(Int64.init) else {
                status = "Secure frame missing sequence"
                return
            }
            guard seq > lastInboundSeq else {
                status = "Replay detected: dropped stale frame"
                return
            }
            lastInboundSeq = seq

            guard let imageString = decrypted["image"] as? String else { return }
            let prefix = "data:image/jpeg;base64,"
            guard imageString.hasPrefix(prefix) else { return }
            let raw = String(imageString.dropFirst(prefix.count))
            guard let data = Data(base64Encoded: raw), let image = UIImage(data: data) else { return }
            frameImage = image
            status = "Live (E2E)"
        } catch {
            status = "Secure frame decrypt failed"
        }
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
