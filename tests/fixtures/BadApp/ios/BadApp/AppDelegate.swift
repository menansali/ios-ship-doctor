import UIKit
import AVFoundation
import WebKit

// Deliberately problematic for test coverage:
// - AVCaptureDevice  → needs NSCameraUsageDescription (missing in Info.plist)
// - UserDefaults     → required-reason API, no PrivacyInfo.xcprivacy present
// - UIWebView        → banned API
class AppDelegate: NSObject {
    let defaults = UserDefaults.standard
    var camera: AVCaptureDevice?
    var legacyWeb: UIWebView?
}
