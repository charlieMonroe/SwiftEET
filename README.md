# SwiftEET
EET (Czech Registration of Sales) in Swift

Česky:

"Knihovna" pro EET napsaná ve Swiftu. Vyžaduje XUCore (https://github.com/charlieMonroe/XUCore/).

Příklad použití:

```swift
let zeroPayment = XUEETCommunicator.PaymentCommand.PaymentAmount.VATPayment(vatExclusive: NSDecimalNumber.zero, vat: NSDecimalNumber.zero)
let amount = XUEETCommunicator.PaymentCommand.PaymentAmount(total: NSDecimalNumber.zero, baseRateVATPayment: zeroPayment, loweredRateVATPayment: zeroPayment)
let paymentCommand = XUEETCommunicator.PaymentCommand(documentNumber: "00001", paymentAmount: amount, transactionDate: Date())

let communicator = try XUEETCommunicator(account: self.account)
let response = try communicator.sendPayment(paymentCommand, validatingOnly: true)
```

Pokud máte nějaké dotazy, pište.
