# SwiftEET
EET (Czech Registration of Sales) in Swift

Česky:

"Knihovna" pro EET napsaná ve Swiftu. Vyžaduje XUCore (https://github.com/charlieMonroe/XUCore/).

Příklad použití:

```swift
let zeroPayment = XUEETCommunicator.PaymentCommand.PaymentAmount.VATPayment(vatExclusive: NSDecimalNumber.zero, vat: NSDecimalNumber.zero)
let amount = XUEETCommunicator.PaymentCommand.PaymentAmount(total: NSDecimalNumber.zero, baseRateVATPayment: zeroPayment, loweredRateVATPayment: zeroPayment)
let paymentCommand = XUEETCommunicator.PaymentCommand(documentNumber: "00001", paymentAmount: amount, transactionDate: Date())

let vatRegistrationNumber = "CZ0101010101"
let localeSpecificData = XUCzechLocaleSpecificPreferencesData()

// ... fill localeSpecificData.

let communicator = try XUEETCommunicator(localeSpecificData: localeSpecificData, vatRegistrationID: vatRegistrationNumber)
let response = try communicator.sendPayment(paymentCommand, validatingOnly: true)
```

Pokud máte nějaké dotazy, pište.
