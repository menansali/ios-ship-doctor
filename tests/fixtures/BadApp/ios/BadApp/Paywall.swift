import SwiftUI
import StoreKit

// Deliberately problematic for test coverage:
// - sells an auto-renewable subscription (StoreKit / SKProduct)
// - ships none of the legal links Guideline 3.1.2 demands on a paywall
// - creates accounts (Apple ID sign-in) but offers no way to delete one
struct Paywall: View {
    var product: SKProduct?
    let signIn = ASAuthorizationAppleIDProvider()

    var body: some View {
        Button("Subscribe") { }
    }
}
