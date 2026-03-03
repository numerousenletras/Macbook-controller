import SwiftUI

struct ContentView: View {
    @StateObject private var model = IOSRelayViewModel()

    var body: some View {
        NavigationStack {
            VStack(spacing: 12) {
                TextField("Relay WS URL", text: $model.relayWSURL)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .textFieldStyle(.roundedBorder)

                TextField("6-digit pair code", text: $model.code)
                    .keyboardType(.numberPad)
                    .textFieldStyle(.roundedBorder)

                HStack {
                    Button("Connect") { model.connect() }
                        .buttonStyle(.borderedProminent)

                    Button("Disconnect") { model.disconnect() }
                        .buttonStyle(.bordered)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("E2E Fingerprint")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                    Text(model.e2eFingerprint)
                        .font(.callout.monospaced())
                    HStack {
                        Button("Trust") { model.trustFingerprint() }
                            .buttonStyle(.borderedProminent)
                        Button("Clear") { model.clearTrust() }
                            .buttonStyle(.bordered)
                        Text(model.isFingerprintTrusted ? "Trusted" : "Not Trusted")
                            .foregroundStyle(model.isFingerprintTrusted ? .green : .orange)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                Group {
                    if let image = model.frameImage {
                        GeometryReader { geo in
                            Image(uiImage: image)
                                .resizable()
                                .scaledToFit()
                                .frame(maxWidth: .infinity, maxHeight: .infinity)
                                .background(Color.black)
                                .contentShape(Rectangle())
                                .onTapGesture { location in
                                    let x = max(0, min(1, location.x / geo.size.width))
                                    let y = max(0, min(1, location.y / geo.size.height))
                                    model.sendClick(x: x, y: y)
                                }
                        }
                    } else {
                        ZStack {
                            Rectangle().fill(Color.black)
                            Text("No frame yet")
                                .foregroundStyle(.white.opacity(0.8))
                        }
                    }
                }
                .frame(height: 280)
                .clipShape(RoundedRectangle(cornerRadius: 12))

                HStack {
                    Button("ESC") { model.sendKey("esc") }
                        .buttonStyle(.bordered)
                    Button("Scroll Up") { model.sendScroll(250) }
                        .buttonStyle(.bordered)
                    Button("Scroll Down") { model.sendScroll(-250) }
                        .buttonStyle(.bordered)
                }

                HStack {
                    TextField("Type text", text: $model.textToSend)
                        .textFieldStyle(.roundedBorder)
                    Button("Send") { model.sendText() }
                        .buttonStyle(.borderedProminent)
                }

                Text(model.status)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)

                Text("Compare fingerprint with Mac before trusting. Rekeying happens automatically every 5 minutes or 300 encrypted messages.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            .padding()
            .navigationTitle("Macbook Controller")
        }
    }
}
