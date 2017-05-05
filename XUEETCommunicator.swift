//
//  XUEETHelper.swift
//  UctoXCore
//
//  Created by Charlie Monroe on 11/24/16.
//  Copyright © 2016 Charlie Monroe Software. All rights reserved.
//

import Foundation
import Security
import XUCore

#if os(iOS)
	import KissXML
	import AEXML
	import SwiftyRSA
	
	typealias XUXMLElement = DDXMLElement
#else
	typealias XUXMLElement = XMLElement
#endif

private let _dateFormatter: DateFormatter = {
	let dateFormatter = DateFormatter()
	dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
	return dateFormatter
}()


private extension XUXMLElement {
	
	var canonicalXMLString: String {
		var result = "<\(self.name!)"
		if var attributes = self.attributes, !attributes.isEmpty {
			attributes.sort(by: {
				let name1 = $0.name!
				let name2 = $1.name!
				if name1.hasPrefix("xmlns") {
					if name2.hasPrefix("xmlns") {
						return name1 < name2
					}
					
					return true
				}
				
				if name2.hasPrefix("xmlns") {
					return false
				}
				
				return name1 < name2
			})
			
			result += " "
			result += attributes.map({ $0.xmlString }).joined(separator: " ")
		}
		
		result += ">"
		
		if let children = self.children?.flatMap({ $0 as? XUXMLElement }), !children.isEmpty {
			result += children.map({ $0.canonicalXMLString }).joined()
		} else if let stringValue = self.stringValue {
			result += stringValue
		}
		
		result += "</\(self.name!)>"
		
		return result
	}
	
	#if os(iOS)
	func addAttribute(named name: String, withStringValue stringValue: String) {
		self.addAttribute(withName: name, stringValue: stringValue)
	}
	
	func setAttributesWith(_ attributes: [String : String]) {
		for (name, value) in attributes {
			self.addAttribute(withName: name, stringValue: value)
		}
	}
	
	convenience init(name: String, attributes: [String: String]) {
		self.init(name: name)
		
		self.setAttributesWith(attributes: attributes)
	}
	#endif
	
}


#if os(iOS)
	
	private extension XUDownloadCenter {
		func downloadXMLDocument(at url: URL!, withRequestModifier modifier: (inout URLRequest) -> Void) -> AEXMLDocument? {
			guard let source = self.downloadWebPage(at: url, withRequestModifier: modifier) else {
				return nil
			}
			
			let options = AEXMLOptions()
			return try? AEXMLDocument(xml: source, encoding: .utf8, options: options)
		}
	}
	
	private extension AEXMLElement {
		
		func firstNode(onXPath xPath: String) -> AEXMLElement? {
			let pathComponents = xPath.components(separatedBy: "/")
			
			var element = self
			for component in pathComponents {
				if component.hasPrefix("@") {
					fatalError("Attributes are not supported as entities in AEXML.")
				}
				
				element = element[component]
				if element.error != nil {
					return nil
				}
			}
			
			return element
		}
		
		func nodes(forXPath xPath: String) -> [AEXMLElement] {
			guard let element = self.firstNode(onXPath: xPath) else {
				return []
			}
			
			return element.all
		}
		
		func stringValue(ofFirstNodeOnXPath xPath: String) -> String? {
			let pathComponents = xPath.components(separatedBy: "/")
			
			var element = self
			for component in pathComponents {
				if component.hasPrefix("@") {
					return element.attributes[component.deleting(prefix: "@")]
				}
				
				element = element[component]
				if element.error != nil {
					return nil
				}
			}
			
			return element.stringValue
		}
		
	}
	
#endif

public final class XUEETCommunicator {
	
	/// Command for a payment.
	public struct PaymentCommand {
		
		/// Amount paid.
		public struct PaymentAmount {
			
			/// VAT payment. Contains VAT exclusive amount and VAT amount.
			public struct VATPayment {
				
				/// VAT Exclusive.
				public let vatExclusive: NSDecimalNumber
				
				/// VAT.
				public let vat: NSDecimalNumber
				
				public init(vatExclusive: NSDecimalNumber, vat: NSDecimalNumber) {
					self.vatExclusive = vatExclusive
					self.vat = vat
				}
				
			}
			
			/// VAT payment at base rate.
			public let baseRateVATPayment: VATPayment
			
			/// VAT payment at lowered rate.
			public let loweredRateVATPayment: VATPayment
			
			/// Total amount.
			public let total: NSDecimalNumber
			
			public init(total: NSDecimalNumber, baseRateVATPayment: VATPayment, loweredRateVATPayment: VATPayment) {
				self.baseRateVATPayment = baseRateVATPayment
				self.loweredRateVATPayment = loweredRateVATPayment
				self.total = total
			}
			
		}
		
		/// Command UUID.
		public let commandUUID: String = {
			return UUID().uuidString
		}()
		
		/// Number of the document. E.g. 000001
		public let documentNumber: String
		
		/// The amount paid.
		public let paymentAmount: PaymentAmount
		
		/// Date of the transaction.
		public let transactionDate: Date
		
		public init(documentNumber: String, paymentAmount: PaymentAmount, transactionDate: Date) {
			self.documentNumber = documentNumber
			self.paymentAmount = paymentAmount
			self.transactionDate = transactionDate
		}
		
	}
	
	/// A response from the EET server.
	public enum PaymentResponse {
		
		/// Payload in case of success.
		public struct Payload: CustomStringConvertible {
			
			/// BKP.
			public let bkp: String
			
			/// The date string.
			public let dateString: String
			
			/// FIK code.
			public let fik: String
			
			/// Message UUID.
			public let messageUUID: String
			
			/// Possible warnings.
			public let warnings: [String]
			
			
			public var description: String {
				var description = ""
				description += "BKP:\n\(self.bkp)\n\n"
				description += "Datum přijetí:\n\(self.dateString)\n\n"
				description += "FIK:\n\(self.fik)\n\n"
				description += "UUID zprávy:\n\(messageUUID)"
				
				if !self.warnings.isEmpty {
					description += "\n\nVarování:\n"
					description += self.warnings.flatMap({ "• " + $0 }).joined(separator: "\n")
				}
				
				return description
			}
			
		}
		
		public struct Error: CustomStringConvertible {
			
			/// Errors.
			public let errors: [String]
			
			/// Possible additional warnings.
			public let warnings: [String]
			
			public var description: String {
				var errorText = self.errors.flatMap({ "• " + $0 }).joined(separator: "\n")
				if !self.warnings.isEmpty {
					errorText += "\n\nVarování:\n"
					errorText += self.warnings.flatMap({ "• " + $0 }).joined(separator: "\n")
				}
				return errorText
			}
			
		}
		
		/// Success with the required data.
		case success(Payload)
		
		/// An error with multiple error strings.
		case error(Error)
		
	}
	
	public enum InitializationError: Error {
		
		/// Error with an error message.
		case errorString(String)
		
		/// Error represented by OSStatus. You should use
		/// SecCopyErrorMessageString(status, nil) to make this into a string.
		case errorCode(OSStatus)
	}
	
	public enum SendingError: Error {
		case cannotSerializeXML
		case coreFoundationError(CFError)
		case invalidResponse
		case localeSpecificDataMissing
		case localeSpecificDataIncomplete
		case macOSSierraRequired
		case networkError
		case unknownError
		
		public var localizedDescription: String {
			switch self {
			case .cannotSerializeXML:
				return "Chyba při vytváření XML dokumentu."
			case .coreFoundationError(let error):
				return error.localizedDescription
			case .invalidResponse:
				return "Špatná odpověď serveru."
			case .localeSpecificDataIncomplete:
				return "Převolby k EET nejsou vyplněny."
			case .localeSpecificDataMissing:
				return "Převolby k EET chybí."
			case .macOSSierraRequired:
				return "Pro EET je třeba mít macOS 10.12 nebo novější."
			case .networkError:
				return "Chyba sítě - nelze načíst odpověď."
			case .unknownError:
				return "Nastala neznámá chyba."
			}
		}
	}
	
	/// EET certificate.
	public let certificate: XUCzechLocaleSpecificPreferencesData.EET.Certificate
	
	/// Czech locale specific data.
	public let localeSpecificData: XUCzechLocaleSpecificPreferencesData
	
	/// VAT registration ID - "DIČ".
	public let vatRegistrationID: String
	
	private func _createControlCodesElement(withCommand command: PaymentCommand) throws -> XUXMLElement {
		let element = XUXMLElement(name: "KontrolniKody")
		let children = try self._generatePKPandBKP(forCommand: command)
		children.forEach({ element.addChild($0) })
		return element
	}
	
	private func _createDataElement(withCommand command: PaymentCommand) throws -> XUXMLElement {
		guard let premisesID = self.localeSpecificData.eetData.premisesID else {
			throw SendingError.localeSpecificDataIncomplete
		}
		
		let element = XUXMLElement(name: "Data")
		var atts: [String : String] = [
			"dic_popl": self.vatRegistrationID,
			"id_provoz": premisesID,
			"id_pokl": self.localeSpecificData.eetData.cashRegisterID,
			"porad_cis": command.documentNumber,
			"dat_trzby": _dateFormatter.string(from: command.transactionDate),
			"celk_trzba": String(format: "%0.2f", command.paymentAmount.total.doubleValue),
			"rezim": "0"
		]
		
		if !command.paymentAmount.baseRateVATPayment.vatExclusive.isZero {
			atts += [
				"zakl_dan1": String(format: "%0.2f", command.paymentAmount.baseRateVATPayment.vatExclusive.doubleValue),
				"dan1": String(format: "%0.2f", command.paymentAmount.baseRateVATPayment.vat.doubleValue)
			]
		}
		
		if !command.paymentAmount.loweredRateVATPayment.vatExclusive.isZero {
			atts += [
				"zakl_dan2": String(format: "%0.2f", command.paymentAmount.loweredRateVATPayment.vatExclusive.doubleValue),
				"dan2": String(format: "%0.2f", command.paymentAmount.loweredRateVATPayment.vat.doubleValue)
			]
		}
		
		element.setAttributesWith(atts)
		return element
	}
	
	private func _createHeaderElement(withUUID uuid: String, validatingOnly: Bool) -> XUXMLElement {
		let element = XUXMLElement(name: "Hlavicka")
		let date = Date()
		
		var atts = [
			"uuid_zpravy": uuid,
			"dat_odesl": _dateFormatter.string(from: date),
			"prvni_zaslani": "1"
		]
		
		if validatingOnly {
			atts["overeni"] = "1"
		}
		
		element.setAttributesWith(atts)
		return element
	}
	
	private func _createSignedInfoElement(withDigest digest: String, andBodyUUID bodyUUID: String) -> XUXMLElement {
		let signedInfoElement = XUXMLElement(name: "ds:SignedInfo")
		let canonicalizationMethodElement = XUXMLElement(name: "ds:CanonicalizationMethod", attributes: [
				"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
			])
		canonicalizationMethodElement.addChild(XUXMLElement(name: "ec:InclusiveNamespaces", attributes: [
				"xmlns:ec": "http://www.w3.org/2001/10/xml-exc-c14n#",
				"PrefixList": "soap"
			]))
		signedInfoElement.addChild(canonicalizationMethodElement)
		
		signedInfoElement.addChild(XUXMLElement(name: "ds:SignatureMethod", attributes: [
				"Algorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
			]))
		
		let referenceElement = XUXMLElement(name: "ds:Reference", attributes: [
				"URI": "#id-\(bodyUUID)"
			])
		
		let transformsElement = XUXMLElement(name: "ds:Transforms")
		let transformElement = XUXMLElement(name: "ds:Transform", attributes: [
				"Algorithm": "http://www.w3.org/2001/10/xml-exc-c14n#"
			])
		transformElement.addChild(XUXMLElement(name: "ec:InclusiveNamespaces", attributes: [
				"xmlns:ec": "http://www.w3.org/2001/10/xml-exc-c14n#",
				"PrefixList": ""
			]))
		
		transformsElement.addChild(transformElement)
		referenceElement.addChild(transformsElement)
		
		referenceElement.addChild(XUXMLElement(name: "ds:DigestMethod", attributes: [
				"Algorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
			]))
		
		referenceElement.addChild(XUXMLElement(name: "ds:DigestValue", stringValue: digest))
		
		signedInfoElement.addChild(referenceElement)
		return signedInfoElement
	}
	
	private func _generatePKPandBKP(forCommand command: PaymentCommand) throws -> [XUXMLElement] {
		let localeData = self.localeSpecificData
		
		let plaintext = [
			self.vatRegistrationID,
			localeData.eetData.premisesID!,
			localeData.eetData.cashRegisterID,
			command.documentNumber,
			_dateFormatter.string(from: command.transactionDate),
			String(format: "%0.2f", command.paymentAmount.total.doubleValue)
		].joined(separator: "|")
		
		let signedData: Data
		
		#if os(iOS)
			do {
				let swiftyRsa = SwiftyRSA()
				signedData = try swiftyRsa.signData(plaintext.data(using: .ascii)!, privateKey: self.certificate.privateKey, digestMethod: .SHA256)
			} catch let error {
				print(error)
				throw error
			}
		#else
			var error: Unmanaged<CFError>?
			guard let signer = SecSignTransformCreate(self.certificate.privateKey, &error) else {
				if let err = error?.takeRetainedValue() {
					throw SendingError.coreFoundationError(err)
				} else {
					throw SendingError.unknownError
				}
			}
			
			guard SecTransformSetAttribute(signer, kSecTransformInputAttributeName, plaintext.data(using: .ascii)! as CFData, &error) else {
				if let err = error?.takeRetainedValue() {
					throw SendingError.coreFoundationError(err)
				} else {
					throw SendingError.unknownError
				}
			}
			
			guard SecTransformSetAttribute(signer, kSecDigestTypeAttribute, kSecDigestSHA2, &error) else {
				if let err = error?.takeRetainedValue() {
					throw SendingError.coreFoundationError(err)
				} else {
					throw SendingError.unknownError
				}
			}
			
			let digestLength: CFNumber = 256 as CFNumber
			guard SecTransformSetAttribute(signer, kSecDigestLengthAttribute, digestLength, &error) else {
				if let err = error?.takeRetainedValue() {
					throw SendingError.coreFoundationError(err)
				} else {
					throw SendingError.unknownError
				}
			}
			
			error = nil
			
			guard let data = SecTransformExecute(signer, &error) as? Data else {
				if let err = error?.takeRetainedValue() {
					throw SendingError.coreFoundationError(err)
				} else {
					throw SendingError.unknownError
				}
			}
			
			signedData = data
		#endif
		
		
		let signature = signedData.base64EncodedString()
		let pkpElement = XUXMLElement(name: "pkp", stringValue: signature)
		pkpElement.setAttributesWith([
			"digest": "SHA256",
			"cipher": "RSA2048",
			"encoding": "base64"
		])
		
		var bkpRaw = signedData.sha1Digest
		assert(bkpRaw.characters.count == 40)
		
		var bkpParts: [String] = []
		while !bkpRaw.isEmpty {
			let prefix = bkpRaw.prefix(ofLength: 8)
			bkpRaw = bkpRaw.deleting(prefix: prefix)
			bkpParts.append(prefix)
		}
		
		let bkpElement = XUXMLElement(name: "bkp", stringValue: bkpParts.joined(separator: "-"))
		bkpElement.setAttributesWith([
			"digest": "SHA1",
			"encoding": "base16"
		])
		return [pkpElement, bkpElement]
	}
	
	private func _generateSOAPHeader(from soapBody: XUXMLElement, withBodyUUID bodyUUID: String) throws -> XUXMLElement {
		let headerElement = XUXMLElement(name: "SOAP-ENV:Header", attributes: [
				"xmlns:SOAP-ENV": "http://schemas.xmlsoap.org/soap/envelope/"
			])
		
		let securityElement = XUXMLElement(name: "wsse:Security", attributes: [
				"xmlns:wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
				"xmlns:wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
				"soap:mustUnderstand": "1"
			])
		
		let binarySecurityTokenUUID = UUID().uuidString
		let binarySecurityTokenElement = XUXMLElement(name: "wsse:BinarySecurityToken", attributes: [
				"EncodingType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary",
				"ValueType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3",
				"wsu:Id": "X509-\(binarySecurityTokenUUID)"
			])
		
		guard !self.certificate.certificateChain.isEmpty else {
			throw SendingError.localeSpecificDataIncomplete
		}
		
		let certificateData = SecCertificateCopyData(self.certificate.certificateChain[0]) as Data
		binarySecurityTokenElement.stringValue = certificateData.base64EncodedString()
		securityElement.addChild(binarySecurityTokenElement)
		
		let signatureElement = XUXMLElement(name: "ds:Signature", attributes: [
				"xmlns:ds": "http://www.w3.org/2000/09/xmldsig#",
				"Id": "SIG-\(UUID().uuidString)"
			])
		
		let bodyCopy = soapBody.copy() as! XUXMLElement
		bodyCopy.addAttribute(named: "xmlns:soap", withStringValue: "http://schemas.xmlsoap.org/soap/envelope/")
		
		let canonicalXMLString = bodyCopy.canonicalXMLString
		
		
		guard let bodyData = canonicalXMLString.data(using: .utf8) else {
			throw SendingError.cannotSerializeXML
		}
		
		let signedInfoElement = self._createSignedInfoElement(withDigest: (bodyData as NSData).sha256Digest().base64EncodedString(), andBodyUUID: bodyUUID)
		signatureElement.addChild(signedInfoElement)
		
		let signedInfoCopy = signedInfoElement.copy() as! XUXMLElement
		signedInfoCopy.addAttribute(named: "xmlns:soap", withStringValue: "http://schemas.xmlsoap.org/soap/envelope/")
		signedInfoCopy.addAttribute(named: "xmlns:ds", withStringValue: "http://www.w3.org/2000/09/xmldsig#")
		
		guard let signatureInfoData = signedInfoCopy.canonicalXMLString.data(using: .utf8) else {
			throw SendingError.cannotSerializeXML
		}
		
		let signatureValue = try self.certificate.signDataUsingRSASHA256(signatureInfoData)
		signatureElement.addChild(XUXMLElement(name: "ds:SignatureValue", stringValue: signatureValue))
		
		let keyInfoElement = XUXMLElement(name: "ds:KeyInfo", attributes: [
				"Id": "KI-\(UUID().uuidString)"
			])
		
		let securityTokenReferenceElement = XUXMLElement(name: "wsse:SecurityTokenReference", attributes: [
				"xmlns:wsse": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd",
				"xmlns:wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
				"wsu:Id": "STR-\(UUID().uuidString)"
			])
		securityTokenReferenceElement.addChild(XUXMLElement(name: "wsse:Reference", attributes: [
				"URI": "#X509-\(binarySecurityTokenUUID)",
				"ValueType": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
			]))
		
		keyInfoElement.addChild(securityTokenReferenceElement)
		signatureElement.addChild(keyInfoElement)
		securityElement.addChild(signatureElement)
		headerElement.addChild(securityElement)
		return headerElement
	}
	
	/// Initializes self with required information. Will throw if the certificate
	/// can't be found or if it cannot be validated (see validateCertificate()).
	/// Always throws InitializationError.
	public init(localeSpecificData: XUCzechLocaleSpecificPreferencesData, vatRegistrationID: String) throws {
		self.localeSpecificData = localeSpecificData
		self.vatRegistrationID = vatRegistrationID
		
		guard let certificate = localeSpecificData.eetData.certificate else {
			throw InitializationError.errorString("Není nainstalovaný certifikát do tohoto účtu.")
		}
		
		self.certificate = certificate
		
		try self.validateCertificate()
	}
	
	/// Sends a payment command. If validatingOnly is set to true, the command
	/// will be executed with the testing flag.
	///
	/// Throws a SendingError.
	public func sendPayment(_ payment: PaymentCommand, validatingOnly: Bool = false, testMode: Bool = XUAppSetup.isRunningInDebugMode) throws -> PaymentResponse {
		let header = self._createHeaderElement(withUUID: payment.commandUUID, validatingOnly: validatingOnly)
		let data = try self._createDataElement(withCommand: payment)
		let controlCodes = try self._createControlCodesElement(withCommand: payment)
		let saleElement = XUXMLElement(name: "Trzba", attributes: [
				"xmlns": "http://fs.mfcr.cz/eet/schema/v3"
			])
		
		saleElement.addChild(header)
		saleElement.addChild(data)
		saleElement.addChild(controlCodes)
		
		let soapEnvelope = XUXMLElement(name: "soap:Envelope", attributes: [
				"xmlns:soap": "http://schemas.xmlsoap.org/soap/envelope/"
			])
		
		let soapBodyUUID = UUID().uuidString
		let soapBody = XUXMLElement(name: "soap:Body", attributes: [
				"xmlns:wsu": "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
				"wsu:Id": "id-\(soapBodyUUID)"
			])
		
		soapBody.addChild(saleElement)
		
		let soapHeader = try self._generateSOAPHeader(from: soapBody, withBodyUUID: soapBodyUUID)
		
		soapEnvelope.addChild(soapHeader)
		soapEnvelope.addChild(soapBody)
		
		let downloadCenter = XUDownloadCenter(owner: self)
		let soapURLString: String
		
		if testMode {
			soapURLString = "https://pg.eet.cz/eet/services/EETServiceSOAP/v3"
		} else {
			soapURLString = "https://prod.eet.cz:443/eet/services/EETServiceSOAP/v3"
		}
		
		guard let responseXML = downloadCenter.downloadXMLDocument(at: URL(string: soapURLString), withRequestModifier: { (request: inout URLRequest) in
			request["SOAPAction"] = "http://fs.mfcr.cz/eet/OdeslaniTrzby"
			request.acceptType = "text/xml; charset=UTF-8"
			request.contentType = "text/xml; charset=UTF-8"
			request.httpMethod = "POST"
			
			let xmlString = soapEnvelope.canonicalXMLString
			let xmlStringFixup = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + xmlString + "\n"
			let xmlData = xmlStringFixup.data(using: .utf8)!
			
			try? xmlData.write(to: URL(fileURLWithPath: NSTemporaryDirectory()).appendingPathComponent("message.xml"))
			
			request.httpBody = xmlData
			request["Content-Length"] = "\(xmlData.count)"
		}) else {
			throw SendingError.networkError
		}
		
		guard let answerNode = responseXML.firstNode(onXPath: "soapenv:Envelope/soapenv:Body/eet:Odpoved") else {
			XULog("No soapenv:Body in \(responseXML)")
			throw SendingError.invalidResponse
		}
		
		let errorNodes = answerNode.nodes(forXPath: "eet:Chyba")
		let warnings = answerNode.nodes(forXPath: "eet:Varovani").flatMap({ $0.stringValue })
		if !errorNodes.isEmpty {
			XULog("Found errors in \(responseXML)")
			
			let errors = errorNodes.flatMap({ $0.stringValue })
			return PaymentResponse.error(XUEETCommunicator.PaymentResponse.Error(errors: errors, warnings: warnings))
		}
		
		guard
			let bkp = answerNode.stringValue(ofFirstNodeOnXPath: "eet:Hlavicka/@bkp"),
			let dateString = answerNode.stringValue(ofFirstNodeOnXPath: "eet:Hlavicka/@dat_prij"),
			let fik = answerNode.stringValue(ofFirstNodeOnXPath: "eet:Potvrzeni/@fik"),
			let messageUUID = answerNode.stringValue(ofFirstNodeOnXPath: "eet:Hlavicka/@uuid_zpravy")
		else {
			XULog("Did not find one of the required values in \(responseXML)")
			throw SendingError.invalidResponse
		}
		
		let payload = PaymentResponse.Payload(bkp: bkp, dateString: dateString, fik: fik, messageUUID: messageUUID, warnings: warnings)
		return PaymentResponse.success(payload)
	}
	
	/// Validates the certificate. It is automatically called within init(account:)
	/// but can be rechecked, e.g. if an instance of this helper is kept for
	/// a longer period of time. Always throws InitializationError.
	public func validateCertificate() throws {
		for certificate in self.certificate.certificateChain {
			let policy = SecPolicyCreateBasicX509()
			var trust: SecTrust?
			let trustStatus = SecTrustCreateWithCertificates(certificate, policy, &trust)
			guard trust != nil else {
				throw InitializationError.errorCode(trustStatus)
			}
			
			var evaluationResult: SecTrustResultType = SecTrustResultType.fatalTrustFailure
			SecTrustEvaluate(trust!, &evaluationResult)
			
			guard evaluationResult == .unspecified || evaluationResult == .proceed else {
				throw InitializationError.errorString("Certifikát není validní. Zkontrolujte, zda nevypršel a zda máte nainstalovaný i kořenový certifikát.")
			}
		}
	}
	
}

extension XUEETCommunicator: XUDownloadCenterOwner {
	
	public func downloadCenter(_ downloadCenter: XUDownloadCenter, didEncounterError error: XUDownloadCenterError) {
		// No-op
	}
	
	public var name: String {
		return "EET"
	}
	
}
