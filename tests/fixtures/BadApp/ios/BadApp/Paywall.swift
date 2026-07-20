import SwiftUI
import StoreKit
import GoogleSignIn

// Deliberately problematic for test coverage:
// - sells an auto-renewable subscription (StoreKit / SKProduct)
// - ships none of the legal links Guideline 3.1.2 demands on a paywall
// - offers Google sign-in with no Apple equivalent (4.8)
// - creates accounts but offers no way to delete one (5.1.1(v))
// - leaves template junk in shipped strings (2.1)
struct Paywall: View {
    var product: SKProduct?
    let signIn = GIDSignIn.sharedInstance
    let apiKey = "YOUR_API_KEY_HERE"
    let blurb = "Lorem ipsum dolor sit amet, consectetur adipiscing elit."
    let support = "test@example.com"

    var body: some View {
        Button("Subscribe") { }
    }
}
