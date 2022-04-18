// --------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation. All rights reserved.
//
// The MIT License (MIT)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the ""Software""), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED *AS IS*, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
// IN THE SOFTWARE.
//
// --------------------------------------------------------------------------

import AzureCore
import CommonCrypto
import CryptoKit
import Foundation

class CryptoUtils {
    static let ciperModeSize: Int = 1
    static let initializationVectorSize: Int = 16
    static let hmacSize: Int = 32

    static func extractCipherMode(result: [UInt8]) -> [UInt8] {
        return copyOfRange(originalArr: result, startIdx: 0, endIdx: ciperModeSize)
    }

    static func extractInitializationVector(result: [UInt8]) -> [UInt8] {
        return copyOfRange(
            originalArr: result,
            startIdx: ciperModeSize,
            endIdx: ciperModeSize + initializationVectorSize
        )
    }

    static func extractCipherText(result: [UInt8]) -> [UInt8] {
        return copyOfRange(
            originalArr: result,
            startIdx: ciperModeSize + initializationVectorSize,
            endIdx: ciperModeSize + initializationVectorSize +
                (result.count - hmacSize - ciperModeSize - initializationVectorSize)
        )
    }

    static func extractHmac(result: [UInt8]) -> [UInt8] {
        let testArr1 = copyOfRange(originalArr: result, startIdx: result.count - hmacSize, endIdx: result.count)
        print("Print hmac:", String(decoding: testArr1, as: UTF8.self))
        return testArr1
    }

    static func extractCipherModeIVCipherText(result: [UInt8]) -> [UInt8] {
        let testArr = copyOfRange(originalArr: result, startIdx: 0, endIdx: result.count - hmacSize)
        print("Print cipherModeIVText:", String(decoding: testArr, as: UTF8.self))
        return testArr
    }
}

func copyOfRange(originalArr: [UInt8], startIdx: Int, endIdx: Int) -> [UInt8] {
    var arrCopy = [UInt8](repeating: 0, count: endIdx - startIdx)
    for idx in startIdx ..< endIdx {
        arrCopy[idx - startIdx] = originalArr[idx]
    }
    return arrCopy
}

// Generate HMAC SHA256 signature using CryptoKit Library
func verifyEncryptedPayload(cipherModeIVCipherText: [UInt8], authKey: String, actualHmac: [UInt8]) throws -> Bool {
    // 1.Calculate SHA256 key
    guard let data = Data(base64Encoded: authKey) else {
        throw AzureError.client("Failed to convert base64 encoded authKey into Data format.")
    }
    let digest = SHA256.hash(data: data)
    let key = SymmetricKey(data: digest.data)
    // print("Print SymmetricKey String:", getSymmetricKeyString(key: key))

    // 2.Calculate HMAC
    let signature = HMAC<SHA256>.authenticationCode(for: Data(cipherModeIVCipherText), using: key)
    let calculatedMacHex = Data(signature).map { String(format: "%02hhx", $0) }.joined()
    print("calculatedMac:\(calculatedMacHex)")

    // 3.Get actual HMAC
    let actualHmacHex = Data(actualHmac).map { String(format: "%02hhx", $0) }.joined()
    print("actualHmac:\(actualHmacHex)")

    return actualHmacHex == calculatedMacHex
}

/* This is for testing:
 func getSymmetricKeyString(key: SymmetricKey) -> String{
     key.withUnsafeBytes {
         return Data(Array($0)).base64EncodedString()
     }
 }
 */

extension Digest {
    var bytes: [UInt8] { Array(makeIterator()) }
    var data: Data { Data(bytes) }
    var hexStr: String {
        bytes.map { String(format: "%02X", $0) }.joined()
    }
}

// Decrypt the notification payload using CommonCrypto Library
func decryptPushNotificationPayload(cipherText: [UInt8], iv: [UInt8], cryptoKey: String) -> String {
    let decodedData = Data(base64Encoded: cryptoKey)!
    let keyBytes = Array(decodedData)

    let cryptLength = size_t(cipherText.count + kCCBlockSizeAES128)
    var cryptData = [UInt8](repeating: 0, count: cryptLength)

    let keyLength = size_t(kCCKeySizeAES256)
    let algoritm: CCAlgorithm = UInt32(kCCAlgorithmAES)
    let options: CCOptions = UInt32(kCCOptionPKCS7Padding)

    var numBytesEncrypted: size_t = 0

    let cryptStatus = CCCrypt(
        CCOperation(kCCDecrypt),
        algoritm,
        options,
        keyBytes,
        keyLength,
        iv,
        cipherText,
        cipherText.count,
        &cryptData,
        cryptLength,
        &numBytesEncrypted
    )
    if UInt32(cryptStatus) == UInt32(kCCSuccess) {
        cryptData.removeSubrange(numBytesEncrypted ..< cryptData.count)

    } else {
        print("Error: \(cryptStatus)")
    }

    return String(decoding: cryptData, as: UTF8.self)
}

/*
// Interaction with KeyChain: Create, Read & Delete keys
internal func generateAndStoreSymmetricKey(withKeychainTag: String) throws {
    let alias = withKeychainTag
    let key = SymmetricKey(size: .bits256)

    let addQuery: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrLabel: alias,
        kSecAttrAccount: "Account \(alias)",
        kSecAttrService: "Service \(alias)",
        kSecReturnAttributes: true,
        kSecValueData: key.rawRepresentation
    ]

    var result: CFTypeRef?
    let status = SecItemAdd(addQuery as CFDictionary, &result)
    guard status == errSecSuccess else {
        throw AzureError.client("Failed to insert symmetric key into keychain: \(withKeychainTag)")
    }
}

internal func retrieveSymmetricKey(withKeychainTag: String) throws -> SymmetricKey? {
    let alias = withKeychainTag

    // Seek a generic password with the given account.
    let query = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrAccount: "Account \(alias)",
        kSecUseDataProtectionKeychain: true,
        kSecReturnData: true
    ] as [String: Any]

    // Find and cast the result as data.
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    print(status)
    switch status {
    case errSecSuccess:
        guard let data = item as? Data else { throw AzureError.client("Fail to convert the key reference to Data.") }
        // Convert back to a key.
        return try SymmetricKey(rawRepresentation: data)
    case errSecItemNotFound: return nil
    default: throw AzureError.client("Error in reading the key: \(status)")
    }
}

internal func deleteSymmetricKey(withKeychainTag: String) throws {
    let alias = withKeychainTag

    let deleteQuery: [CFString: Any] = [
        kSecClass: kSecClassGenericPassword,
        kSecAttrLabel: alias,
        kSecAttrAccount: "Account \(alias)",
        kSecAttrService: "Service \(alias)"
    ]

    let deleted = SecItemDelete(deleteQuery as CFDictionary)
    guard deleted == errSecSuccess || deleted == errSecItemNotFound else {
        throw AzureError.client("Keychain delete failed: \(withKeychainTag)")
    }
}
 */

protocol GenericPasswordConvertible: CustomStringConvertible {
    /// Creates a key from a raw representation.
    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes

    /// A raw representation of the key.
    var rawRepresentation: Data { get }
}

extension SymmetricKey: GenericPasswordConvertible {
    public var description: String {
        return "symmetrically"
    }

    init<D>(rawRepresentation data: D) throws where D: ContiguousBytes {
        self.init(data: data)
    }

    var rawRepresentation: Data {
        return withUnsafeBytes { Data($0) }
    }

    /// Serializes a `SymmetricKey` to a Base64-encoded `String`.
    func serialize() -> String {
        return withUnsafeBytes { body in
            Data(body).base64EncodedString()
        }
    }
}

extension Date {
    var millisecondsSince1970: Int64 {
        Int64((timeIntervalSince1970 * 1000.0).rounded())
    }

    init(milliseconds: Int64) {
        self = Date(timeIntervalSince1970: TimeInterval(milliseconds) / 1000)
    }
}
