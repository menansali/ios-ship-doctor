import UIKit
import AVFoundation

// Uses the camera (declared) and UserDefaults (declared in PrivacyInfo.xcprivacy).
class AppDelegate: NSObject {
    let defaults = UserDefaults.standard
    var camera: AVCaptureDevice?
}
