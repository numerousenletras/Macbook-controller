import CryptoKit
import Foundation
import SwiftUI
import UIKit

@MainActor
final class IOSRelayViewModel: ObservableObject {
    @Published var relayWSURL = "ws://127.0.0.1:8787"
    @Published var code = ""
    @Published var status = "Idle"
    @Published var frameImage: UIImage?
    @Published var textToSend = ""

    private let session = URLSession(configuration: .default)
    private var socketTask: URLSessionWebSocketTask?

    private var phonePrivateKey: Curve25519.KeyAgreement.PrivateKey?
    private var e2eKey: SymmetricKey?

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
        sendE2EHello()
        receiveLoop()
    }

    func disconnect() {
        phonePrivateKey = nil
        e2eKey = nil
        socketTask?.cancel(with: .normalClosure, reason: nil)
        socketTask = nil
        status = "Disconnected"
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

    private func sendE2EHello() {
        let privateKey = Curve25519.KeyAgreement.PrivateKey()
        phonePrivateKey = privateKey

        let hello: [String: Any] = [
            "type": "e2e_hello",
            "phone_pub": Data(privateKey.publicKey.rawRepresentation).base64EncodedString(),
        ]
        sendRaw(hello)
    }

    private func sendSecure(_ payload: [String: Any]) {
        guard let key = e2eKey else {
            status = "E2E not ready yet"
            return
        }

        do {
            let encrypted = try CryptoEnvelope.encryptJSONObject(payload, using: key)
            sendRaw(["type": "secure_event", "combined": encrypted])
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
        case "e2e_ack":
            handleE2EAck(obj)
        case "secure_frame":
            handleSecureFrame(obj)
        default:
            break
        }
    }

    private func handleE2EAck(_ obj: [String: Any]) {
        guard let privateKey = phonePrivateKey else {
            status = "Missing phone private key"
            return
        }

        guard let macPubB64 = obj["mac_pub"] as? String,
              let macPubData = Data(base64Encoded: macPubB64) else {
            status = "Invalid E2E ack payload"
            return
        }

        do {
            let macPublicKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: macPubData)
            let sharedSecret = try privateKey.sharedSecretFromKeyAgreement(with: macPublicKey)
            e2eKey = CryptoEnvelope.deriveSymmetricKey(from: sharedSecret)
            status = "Secure E2E session established"
        } catch {
            status = "E2E setup failed: \(error.localizedDescription)"
        }
    }

    private func handleSecureFrame(_ obj: [String: Any]) {
        guard let key = e2eKey else {
            status = "Received secure frame before key"
            return
        }

        guard let combined = obj["combined"] as? String else {
            status = "Invalid secure frame payload"
            return
        }

        do {
            let decrypted = try CryptoEnvelope.decryptJSONObject(combinedB64: combined, using: key)
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
}
