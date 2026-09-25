// A camera view that reads one QR code and hands its string back.
//
// AVFoundation rather than VisionKit's DataScannerViewController: this needs
// exactly one QR payload, not live text selection, and AVCaptureMetadataOutput
// works on every device Arca runs on with no extra capability.
//
// The payload is handed back ONCE and the session stops immediately. A TOTP
// setup QR contains the shared secret — the one string that must not be
// re-emitted into a fistful of callbacks while the sheet animates away.

import AVFoundation
import SwiftUI

struct QRScannerView: View {
    /// Called with the raw QR payload, exactly once.
    let onScan: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var denied = false

    var body: some View {
        NavigationStack {
            Group {
                if denied {
                    // The system prompt was refused at some point. Saying how to
                    // fix it beats a black rectangle.
                    ContentUnavailableView {
                        Label("Camera access is off", systemImage: "video.slash")
                    } description: {
                        Text("Allow camera access for Arca in Settings to scan QR codes.")
                    } actions: {
                        if let url = URL(string: UIApplication.openSettingsURLString) {
                            Link("Open Settings", destination: url)
                        }
                    }
                } else {
                    CameraPreview { payload in
                        onScan(payload)
                        dismiss()
                    }
                    .ignoresSafeArea()
                    .overlay(alignment: .bottom) {
                        Text("Point the camera at the site's QR code")
                            .font(.footnote)
                            .padding(.horizontal, 12)
                            .padding(.vertical, 8)
                            .background(.ultraThinMaterial, in: Capsule())
                            .padding(.bottom, 24)
                    }
                }
            }
            .navigationTitle("Scan QR Code")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
            }
            .task {
                switch AVCaptureDevice.authorizationStatus(for: .video) {
                case .authorized:
                    break
                case .notDetermined:
                    denied = !(await AVCaptureDevice.requestAccess(for: .video))
                default:
                    denied = true
                }
            }
        }
    }
}

/// The AVFoundation half, wrapped for SwiftUI.
private struct CameraPreview: UIViewControllerRepresentable {
    let onScan: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerController {
        let controller = ScannerController()
        controller.onScan = onScan
        return controller
    }

    func updateUIViewController(_ controller: ScannerController, context: Context) {}
}

final class ScannerController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?

    private let session = AVCaptureSession()
    private var delivered = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black

        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else { return }
        session.addInput(input)

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        // Set AFTER addOutput: the available types are empty before the output
        // joins a session, and setting them early throws.
        output.metadataObjectTypes = [.qr]

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        view.layer.sublayers?.first(where: { $0 is AVCaptureVideoPreviewLayer })?
            .frame = view.bounds
    }

    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        // startRunning blocks; Apple documents it as a background-queue call.
        if !session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [session] in
                session.startRunning()
            }
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning {
            DispatchQueue.global(qos: .userInitiated).async { [session] in
                session.stopRunning()
            }
        }
    }

    nonisolated func metadataOutput(
        _ output: AVCaptureMetadataOutput,
        didOutput metadataObjects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        // The payload is extracted OUT HERE: AVMetadataObject is not Sendable,
        // so it must not cross into the actor hop — a String can.
        guard let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              object.type == .qr,
              let payload = object.stringValue
        else { return }
        // The protocol is not actor-aware, but the delegate queue IS main (set
        // in viewDidLoad), so assuming isolation states a fact rather than
        // hoping one. If the queue ever changes, this traps in debug instead of
        // racing in release.
        MainActor.assumeIsolated {
            // Once. The camera keeps seeing the same code thirty times a
            // second, and the payload is a shared secret — one delivery, then
            // silence.
            guard !delivered else { return }
            delivered = true
            // stopRunning() blocks until the capture pipeline has torn down —
            // and this delegate runs on the MAIN queue, which is the same queue
            // the session is still trying to deliver frames on. Stopping from
            // here asks the session to drain while holding the thread it drains
            // onto: the UI freezes, and the half-dismissed sheet is left on
            // screen. viewWillAppear/viewWillDisappear already hand the call to
            // a background queue for exactly this reason; so does this one now.
            //
            // The `delivered` latch is set synchronously above, so the frames
            // that keep arriving until the session actually stops are still
            // dropped — the secret is handed back exactly once, as before.
            DispatchQueue.global(qos: .userInitiated).async { [session] in
                session.stopRunning()
            }
            onScan?(payload)
        }
    }
}
