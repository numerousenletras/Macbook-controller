import SwiftUI

struct ContentView: View {
    @StateObject private var model = MacRelayViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Macbook Controller Agent")
                .font(.title2.bold())

            TextField("Relay HTTP URL", text: $model.relayHTTPURL)
                .textFieldStyle(.roundedBorder)
            TextField("Relay WS URL", text: $model.relayWSURL)
                .textFieldStyle(.roundedBorder)
            TextField("Device Token", text: $model.deviceToken)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Start Session") {
                    Task { await model.startSession() }
                }
                .buttonStyle(.borderedProminent)

                Button("Stop") {
                    model.stopSession()
                }
                .buttonStyle(.bordered)
            }

            Text("Pairing Code: \(model.pairingCode)")
                .font(.title3.monospacedDigit())

            VStack(alignment: .leading, spacing: 6) {
                Text("E2E Fingerprint: \(model.e2eFingerprint)")
                    .font(.body.monospaced())
                HStack {
                    Button("Trust Fingerprint") { model.trustFingerprint() }
                        .buttonStyle(.borderedProminent)
                    Button("Clear Trust") { model.clearTrust() }
                        .buttonStyle(.bordered)
                    Text(model.isFingerprintTrusted ? "Trusted" : "Not Trusted")
                        .foregroundStyle(model.isFingerprintTrusted ? .green : .orange)
                }
            }

            Text(model.status)
                .foregroundStyle(.secondary)
                .frame(maxWidth: .infinity, alignment: .leading)

            Text("Compare this fingerprint with iPhone before trusting. Rekeying is automatic every 5 minutes or 300 encrypted messages.")
                .font(.footnote)
                .foregroundStyle(.secondary)

            Text("Grant Accessibility and Screen Recording in System Settings for full control.")
                .font(.footnote)
                .foregroundStyle(.secondary)
        }
        .padding(18)
        .frame(minWidth: 620)
    }
}
