import SwiftUI
import AVFoundation

// Camera is declared via INFOPLIST_KEY_NSCameraUsageDescription, not Info.plist.
// @State must NOT be read as the C function stat() (file-timestamp API).
@main
struct ModernAppApp: App {
    @State private var status = "idle"
    let defaults = UserDefaults.standard
    var camera: AVCaptureDevice?

    var body: some Scene {
        WindowGroup { Text(status) }
    }
}
