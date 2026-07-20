import UIKit
import AVFoundation

// Uses the camera (declared) and UserDefaults (declared in PrivacyInfo.xcprivacy).
class AppDelegate: NSObject {
    let defaults = UserDefaults.standard
    var camera: AVCaptureDevice?

    // Settings screen links out to the privacy policy (required for every app).
    let privacyPolicyURL = URL(string: "https://example.com/privacy")!
}
