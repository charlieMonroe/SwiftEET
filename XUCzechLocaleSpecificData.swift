//
//  XUCzechLocaleSpecificData.swift
//  UctoXCore
//
//  Created by Charlie Monroe on 11/18/16.
//  Copyright © 2016 Charlie Monroe Software. All rights reserved.
//

import Foundation
import Security

#if os(iOS)
	import KissXML
	import SwiftyRSA
#endif

private func _loadCertificateChainAndPrivateKey(from rawData: Data, andPassword password: String) throws -> ([SecCertificate], SecKey) {
	let options: NSDictionary = [kSecImportExportPassphrase: password ]
	var itemsOptional: CFArray?
	
	let status = SecPKCS12Import(rawData as CFData, options as CFDictionary, &itemsOptional)
	
	guard let cfItems = itemsOptional, status == noErr else {
		throw XUCzechLocaleSpecificPreferencesData.EET.Certificate.Error.errorCode(status)
	}
	
	let items = (cfItems as NSArray) as [AnyObject]
	guard
		let itemDictionary = items.first as? [String : Any],
		let identityOpt = itemDictionary[kSecImportItemIdentity as String],
		let certificateOpt = itemDictionary[kSecImportItemCertChain as String]
	else {
		throw XUCzechLocaleSpecificPreferencesData.EET.Certificate.Error.errorString("Soubor PK12 neobsahuje privátní klíč.")
	}
	
	var privateKeyOptional: SecKey?
	let identity = identityOpt as! SecIdentity
	let privateKeyStatus = SecIdentityCopyPrivateKey(identity, &privateKeyOptional)
	
	guard let privateKey = privateKeyOptional, privateKeyStatus == noErr else {
		throw XUCzechLocaleSpecificPreferencesData.EET.Certificate.Error.errorCode(privateKeyStatus)
	}
	
	return ((certificateOpt as! CFArray) as! [SecCertificate], privateKey)
}


public final class XUCzechLocaleSpecificPreferencesData: NSObject, NSCoding {
	
	public final class TaxForm: NSObject, NSCoding {
		
		/// City.
		public var city: String? = ""
		
		/// ID of the data storage.
		public var dataBoxID: String? = ""
		
		/// First name.
		public var firstName: String? = ""
		
		/// House number.
		public var houseNumber: String? = ""
		
		/// Last name.
		public var lastName: String? = ""
		
		/// Phone number.
		public var phoneNumber: String? = ""
		
		/// Street name.
		public var street: String? = ""
		
		/// ZIP code.
		public var zipCode: String? = ""
		
		
		public func encode(with aCoder: NSCoder) {
			aCoder.encode(self.city, forKey: Keys.City)
			aCoder.encode(self.dataBoxID, forKey: Keys.DataBoxID)
			aCoder.encode(self.firstName, forKey: Keys.FirstName)
			aCoder.encode(self.houseNumber, forKey: Keys.HouseNumber)
			aCoder.encode(self.lastName, forKey: Keys.LastName)
			aCoder.encode(self.phoneNumber, forKey: Keys.PhoneNumber)
			aCoder.encode(self.street, forKey: Keys.Street)
			aCoder.encode(self.zipCode, forKey: Keys.ZIPCode)
		}
		
		public override init() {
			super.init()
		}
		
		public init?(coder aDecoder: NSCoder) {
			super.init()
			
			self.city = aDecoder.decodeObject(forKey: Keys.City) as? String
			self.dataBoxID = aDecoder.decodeObject(forKey: Keys.DataBoxID) as? String
			self.firstName = aDecoder.decodeObject(forKey: Keys.FirstName) as? String
			self.houseNumber = aDecoder.decodeObject(forKey: Keys.HouseNumber) as? String
			self.lastName = aDecoder.decodeObject(forKey: Keys.LastName) as? String
			self.phoneNumber = aDecoder.decodeObject(forKey: Keys.PhoneNumber) as? String
			self.street = aDecoder.decodeObject(forKey: Keys.Street) as? String
			self.zipCode = aDecoder.decodeObject(forKey: Keys.ZIPCode) as? String
		}
		
	}
	
	public final class EET: NSObject, NSCoding {
		
		/// Certificate wrapper. Should be initialized with data of a PKCS12
		/// file.
		public final class Certificate: NSObject, NSCoding {
			
			public enum Error: Swift.Error {
				case errorString(String)
				case errorCode(OSStatus)
			}
			
			/// Certificate.
			@nonobjc
			public let certificateChain: [SecCertificate]
			
			/// Password for the rawData.
			public let password: String
			
			/// Private key.
			public let privateKey: SecKey
			
			/// Raw data of the PKCS12 file.
			public let rawData: Data
			
			public func encode(with aCoder: NSCoder) {
				aCoder.encode(self.rawData, forKey: Keys.CertificateData)
				aCoder.encode(self.password, forKey: Keys.Password)
			}
			
			/// Inits with data and password. Always throws Certificate.Error.
			public init(rawData: Data, password: String) throws {
				self.rawData = rawData
				self.password = password
				
				let privates = try _loadCertificateChainAndPrivateKey(from: rawData, andPassword: password)
				self.certificateChain = privates.0
				self.privateKey = privates.1
				
				super.init()
			}
			
			public init?(coder aDecoder: NSCoder) {
				guard
					let data = aDecoder.decodeObject(forKey: Keys.CertificateData) as? Data,
					let password = aDecoder.decodeObject(forKey: Keys.Password) as? String
				else {
					return nil
				}
				
				guard let privates = try? _loadCertificateChainAndPrivateKey(from: data, andPassword: password) else {
					return nil
				}
				
				self.rawData = data
				self.password = password
				self.certificateChain = privates.0
				self.privateKey = privates.1
				
				super.init()
			}
			
			/// Signes data by hashing it using SHA256 and then encrypting result
			/// with RSA. Throws XUEETCommunicator.SendingError on macOS, on iOS
			/// throws whatever SwiftyRSA throws.
			public func signDataUsingRSASHA256(_ data: Data) throws -> String {
				#if os(iOS)
					let swiftyRsa = SwiftyRSA()
					let sign = try swiftyRsa.signData(data, privateKey: privateKey, digestMethod: .SHA256)
					return sign.base64EncodedString()
				#else
					var error: Unmanaged<CFError>?
					guard let signer = SecSignTransformCreate(self.privateKey, &error) else {
						if let err = error?.takeRetainedValue() {
							throw XUEETCommunicator.SendingError.coreFoundationError(err)
						} else {
							throw XUEETCommunicator.SendingError.unknownError
						}
					}
					
					guard SecTransformSetAttribute(signer, kSecTransformInputAttributeName, data as CFData, &error) else {
						if let err = error?.takeRetainedValue() {
							throw XUEETCommunicator.SendingError.coreFoundationError(err)
						} else {
							throw XUEETCommunicator.SendingError.unknownError
						}
					}
					
					guard SecTransformSetAttribute(signer, kSecDigestTypeAttribute, kSecDigestSHA2, &error) else {
						if let err = error?.takeRetainedValue() {
							throw XUEETCommunicator.SendingError.coreFoundationError(err)
						} else {
							throw XUEETCommunicator.SendingError.unknownError
						}
					}
					
					let digestLength: CFNumber = 256 as CFNumber
					guard SecTransformSetAttribute(signer, kSecDigestLengthAttribute, digestLength, &error) else {
						if let err = error?.takeRetainedValue() {
							throw XUEETCommunicator.SendingError.coreFoundationError(err)
						} else {
							throw XUEETCommunicator.SendingError.unknownError
						}
					}
					
					error = nil
					
					guard let signedData = SecTransformExecute(signer, &error) as? Data else {
						if let err = error?.takeRetainedValue() {
							throw XUEETCommunicator.SendingError.coreFoundationError(err)
						} else {
							throw XUEETCommunicator.SendingError.unknownError
						}
					}
					
					let signature = signedData.base64EncodedString()
					return signature
				#endif
			}
		}
		
		/// ID of the cash register. This will return the serial number of the
		/// device this is run on.
		public var cashRegisterID: String = {
			#if os(iOS)
				return UIDevice.current.identifierForVender!.uuidString
			#else
				return XUHardwareInfo.shared.serialNumber
			#endif
		}()
		
		/// Certificate data.
		public var certificate: Certificate?
		
		/// ID of the premises. Used for the id_provoz field.
		public var premisesID: String?
		
		
		public func encode(with aCoder: NSCoder) {
			aCoder.encode(self.certificate, forKey: Keys.CertificateData)
			aCoder.encode(self.premisesID, forKey: Keys.PremisesID)
		}
		
		public override init() {
			super.init()
		}
		
		public init?(coder aDecoder: NSCoder) {
			self.certificate = aDecoder.decodeObject(forKey: Keys.CertificateData) as? Certificate
			self.premisesID = aDecoder.decodeObject(forKey: Keys.PremisesID) as? String
			
			super.init()
		}
		
	}
	
	/// Data in regards to EET.
	public var eetData: EET
	
	/// Variables used on various tax forms.
	public var taxFormData: TaxForm
	
	public func encode(with aCoder: NSCoder) {
		aCoder.encode(self.eetData, forKey: Keys.EETData)
		aCoder.encode(self.taxFormData, forKey: Keys.TaxFormData)
	}
	
	public init(taxFormVariables: TaxForm = TaxForm(), eetData: EET = EET()) {
		self.taxFormData = taxFormVariables
		self.eetData = eetData
		
		super.init()
	}
	
	public init?(coder aDecoder: NSCoder) {
		TaxForm.initialize()
		EET.initialize()
		EET.Certificate.initialize()
		
		self.eetData = (aDecoder.decodeObject(forKey: Keys.EETData) as? EET) ?? EET()
		self.taxFormData = (aDecoder.decodeObject(forKey: Keys.TaxFormData) as? TaxForm) ?? TaxForm()
		
		super.init()
	}
	
}

extension XUCzechLocaleSpecificPreferencesData: NSCopying {
	
	fileprivate struct Keys {
		static let TaxFormData = "TaxFormData"
		static let EETData = "EETData"
	}
	
	public func copy(with zone: NSZone? = nil) -> Any {
		let variables = self.taxFormData.copy() as! TaxForm
		let eetData = self.eetData.copy() as! EET
		let data = XUCzechLocaleSpecificPreferencesData(taxFormVariables: variables, eetData: eetData)
		return data
	}
	
}

extension XUCzechLocaleSpecificPreferencesData.EET: NSCopying {
	
	fileprivate struct Keys {
		static let CertificateData = "CertificateData"
		static let PremisesID = "PremisesID"
	}
	
	public func copy(with zone: NSZone? = nil) -> Any {
		let copy = XUCzechLocaleSpecificPreferencesData.EET()
		copy.certificate = self.certificate?.copy() as? Certificate
		copy.premisesID = self.premisesID
		return copy
	}
	
}

extension XUCzechLocaleSpecificPreferencesData.EET.Certificate: NSCopying {
	
	fileprivate struct Keys {
		static let CertificateData = "CertificateData"
		static let Password = "Password"
	}
	
	public func copy(with zone: NSZone? = nil) -> Any {
		let certificate = try! XUCzechLocaleSpecificPreferencesData.EET.Certificate(rawData: self.rawData, password: self.password)
		return certificate
	}
	
}

extension XUCzechLocaleSpecificPreferencesData.TaxForm: NSCopying {
	
	fileprivate struct Keys {
		static let City = "City"
		static let DataBoxID = "DataBoxID"
		static let FirstName = "FirstName"
		static let HouseNumber = "HouseNumber"
		static let LastName = "LastName"
		static let PhoneNumber = "PhoneNumber"
		static let Street = "Street"
		static let ZIPCode = "ZIPCode"
	}
	
	public func copy(with zone: NSZone? = nil) -> Any {
		let variables = XUCzechLocaleSpecificPreferencesData.TaxForm()
		variables.city = self.city
		variables.dataBoxID = self.dataBoxID
		variables.firstName = self.firstName
		variables.houseNumber = self.houseNumber
		variables.lastName = self.lastName
		variables.phoneNumber = self.phoneNumber
		variables.street = self.street
		variables.zipCode = self.zipCode
		return variables
	}
	
}

