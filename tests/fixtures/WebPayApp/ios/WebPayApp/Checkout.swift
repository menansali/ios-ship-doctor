import SwiftUI
import StripePaymentSheet

// Sells digital credits through Stripe with no StoreKit anywhere → 3.1.1.
// Also declares background audio it never implements → 2.5.4,
// and never renamed the template bundle display name → 2.1.
struct Checkout: View {
    let publishableKey = "pk_test_51H8sampleKEYvalue0000"

    var body: some View {
        Button("Buy 100 credits") { }
    }
}
