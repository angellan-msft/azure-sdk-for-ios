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

@testable import AzureCommunicationChat
import AzureCore
import CommonCrypto
import CryptoKit
import Foundation
import XCTest

class CrytoUtilUnitTests: XCTestCase {
    private let validEncryptedNotificationPayload =
        // swiftlint:disable:next line_length
        "cBVKSMQMmcCXmKpNlWFDaRtVBWHa7zmhKFs1qoF0qbVi/CBPOwr7ngSMdlNJY5rOgwcWwYFGMG2b138Rerb/rB6YBCTlmv59RAfbjiceXyHQwGL7CWGkKJVUlgohjL4VLvSqpYhYzXjpRwRFzbPBCZrEWxB6+j0ZK51robqYpKULXq82BiGrs4WVKgs2AfO41W4tGplLNs2cWHugzXMaGgTSmHkehEHriuVUkVdEkOSLJH+GN/kw/BWLcRyCuJUMBSy30l+N+9+o/ufTX/CTKR5j22Jf5167Ffwr7AGtZGXFxrJ9zHMNbtM5ARqaozYEVaa4apDqHi82euBpe1ofETRCyiYMRThaKQbKlcA9sXPeZxOkjdlf021xaIVipE2cKAbOwaiRkL+rfEdWQHOtxsbyal6uLgf9e5ab2xXni+/9Q8wCkTY2JDrRONHFfAOKPALQPrCoI+KWFcPVenEGV6MzQ0mXpu/osYcZUbmmyhSe5tobaePbfBCDwcTgQ5pAyH7dibxqyi0pSZ1nyOvzY3QrddbqD+6oPCh725E63m3ejC+D+IrliSbrRO0yM7ZMhkG6QcaVYfHI+UYj1G+TKdM44sTQ16A3M5LNpoBTwO35l+VWle4KIu5SadBqao93xVZWmfwwdG2atqx2Vz5ODk0Y7JzRyD6YyXINUyF35APyuBIRk+1yxMKyVh8cW+KiWUo2iljIFZNM4zCcQMkI1xu9MHWJ4AuGE8kGpMljWr+sdocTeFULIHybFeNq7VQGpLyRSprO5YaUz9kOusn9fJMoxocCMu6ggqDNpY4roTSgoawQE81YlcPfDJvdxTWDMjCiysunu4pmYvYu/mG+DFtTFYlBaR2Z4JFuZLvHyWEg/w5Rniv+3b4Va7ypwhDePhRTRdncTDJDuXWAewmj7ss1ujoStsVLerB9wzCnnAwCB0m4hiDaVUvAq0Fk0qOI9BbFKjibH+KwjCoSuKomO7bbLe4ijd3qtlPHJfWv7H8Wm5ho1iViF/h3IgMcT0GdnslNmnuYyFAdB3dM1lisesQr5jvZLYufUeU1OlxY/Rno"

    private let invalidEncryptedNotificationPayload =
        // swiftlint:disable:next line_length
        "aBCKSMQMmcCXmKpNlWFDaRtVBWHa7zmhKFs1qoF0qbVi/CBPOwr7ngSMdlNJY5rOgwcWwYFGMG2b138Rerb/rB6YBCTlmv59RAfbjiceXyHQwGL7CWGkKJVUlgohjL4VLvSqpYhYzXjpRwRFzbPBCZrEWxB6+j0ZK51robqYpKULXq82BiGrs4WVKgs2AfO41W4tGplLNs2cWHugzXMaGgTSmHkehEHriuVUkVdEkOSLJH+GN/kw/BWLcRyCuJUMBSy30l+N+9+o/ufTX/CTKR5j22Jf5167Ffwr7AGtZGXFxrJ9zHMNbtM5ARqaozYEVaa4apDqHi82euBpe1ofETRCyiYMRThaKQbKlcA9sXPeZxOkjdlf021xaIVipE2cKAbOwaiRkL+rfEdWQHOtxsbyal6uLgf9e5ab2xXni+/9Q8wCkTY2JDrRONHFfAOKPALQPrCoI+KWFcPVenEGV6MzQ0mXpu/osYcZUbmmyhSe5tobaePbfBCDwcTgQ5pAyH7dibxqyi0pSZ1nyOvzY3QrddbqD+6oPCh725E63m3ejC+D+IrliSbrRO0yM7ZMhkG6QcaVYfHI+UYj1G+TKdM44sTQ16A3M5LNpoBTwO35l+VWle4KIu5SadBqao93xVZWmfwwdG2atqx2Vz5ODk0Y7JzRyD6YyXINUyF35APyuBIRk+1yxMKyVh8cW+KiWUo2iljIFZNM4zCcQMkI1xu9MHWJ4AuGE8kGpMljWr+sdocTeFULIHybFeNq7VQGpLyRSprO5YaUz9kOusn9fJMoxocCMu6ggqDNpY4roTSgoawQE81YlcPfDJvdxTWDMjCiysunu4pmYvYu/mG+DFtTFYlBaR2Z4JFuZLvHyWEg/w5Rniv+3b4Va7ypwhDePhRTRdncTDJDuXWAewmj7ss1ujoStsVLerB9wzCnnAwCB0m4hiDaVUvAq0Fk0qOI9BbFKjibH+KwjCoSuKomO7bbLe4ijd3qtlPHJfWv7H8Wm5ho1iViF/h3IgMcT0GdnslNmnuYyFAdB3dM1lisesQr5jvZLYufUeU1OlxY/Rnx"

    private let validDecryptedNotificationPayload =
        // swiftlint:disable:next line_length
        #"{"senderId": "8:acs:a1e25fcc-6597-44cf-986b-aa9c82ac12fa_00000010-927e-2349-5896-094822005e99","recipientId": "8:acs:a1e25fcc-6597-44cf-986b-aa9c82ac12fa_00000010-927e-2349-5896-094822005e99","transactionId": "cibtJ+IB0ESeX8Tv+pD5BQ.1.1.1.1.1382503597.1.0","groupId": "19:95b1f47544124405835666fed2241c82@thread.v2","messageId": "1649911874203","collapseId":"+DtIYeuwmgCDWhnEiMHaWTtNwEEcWbC6/uxVPSFpLLs=","messageType": "Text","messageBody": "this is gloria","senderDisplayName": "Chi Liu","clientMessageId": "","originalArrivalTime": "2022-04-14T04:51:14.203Z","priority": "","version": "1649911874203","acsChatMessageMetadata": "{\"additionalProp1\":\"FirstMeta\",\"additionalProp2\":\"{fake:json}\",\"additionalProp3\":\"helloworld\"}"}"#

    private let aesKey = "W+OOsDib0dgVq4BUxj9n3bi32wmpM8TFGZbULwaBi1U="
    private let authKey = "u6cf4JQX1HArhvrdie0Gh1ltAOWRwVuZQShmrXs02uM="

    func test_VerifyEncryptedPayload_WithValidPayload() {
        guard let decodedData = Data(base64Encoded: validEncryptedNotificationPayload) else {
            XCTFail("Creating encrypted notification payload data failed.")
            return
        }
        let encryptedBytes = Array(decodedData)

        let hmac: [UInt8] = CryptoUtils.extractHmac(result: encryptedBytes)
        let cipherModeIVCipherText: [UInt8] = CryptoUtils.extractCipherModeIVCipherText(result: encryptedBytes)

        do {
            let result = try verifyEncryptedPayload(
                cipherModeIVCipherText: cipherModeIVCipherText,
                authKey: authKey,
                actualHmac: hmac
            )
            XCTAssertTrue(result)
        } catch {
            XCTFail("Failed to convert base64 encoded authKey into Data format.")
        }
    }

    func test_VerifyEncryptedPayload_WithInvalidPayload() {
        guard let decodedData = Data(base64Encoded: invalidEncryptedNotificationPayload) else {
            XCTFail("Creating encrypted notification payload data failed.")
            return
        }
        let encryptedBytes = Array(decodedData)

        // split [UInt8] into different blocks
        let hmac: [UInt8] = CryptoUtils.extractHmac(result: encryptedBytes)
        let cipherModeIVCipherText: [UInt8] = CryptoUtils.extractCipherModeIVCipherText(result: encryptedBytes)

        do {
            let result = try verifyEncryptedPayload(
                cipherModeIVCipherText: cipherModeIVCipherText,
                authKey: authKey,
                actualHmac: hmac
            )
            XCTAssertFalse(result)
        } catch {
            XCTFail("Failed to convert base64 encoded authKey into Data format.")
        }
    }

    func test_DecryptNotificationPayload_WithValidPayload() {
        guard let decodedData = Data(base64Encoded: validEncryptedNotificationPayload) else {
            XCTFail("Creating encrypted notification payload data failed.")
            return
        }
        let encryptedBytes = Array(decodedData)

        let iv: [UInt8] = CryptoUtils.extractInitializationVector(result: encryptedBytes)
        let cipherText: [UInt8] = CryptoUtils.extractCipherText(result: encryptedBytes)

        let result = decryptPushNotificationPayload(cipherText: cipherText, iv: iv, cryptoKey: aesKey)
        XCTAssert(result.elementsEqual(validDecryptedNotificationPayload))
    }

    func test_DecryptNotificationPayload_WithInvalidPayload() {
        guard let decodedData = Data(base64Encoded: invalidEncryptedNotificationPayload) else {
            XCTFail("Creating encrypted notification payload data failed.")
            return
        }
        let encryptedBytes = Array(decodedData)

        let iv: [UInt8] = CryptoUtils.extractInitializationVector(result: encryptedBytes)
        let cipherText: [UInt8] = CryptoUtils.extractCipherText(result: encryptedBytes)

        let result = decryptPushNotificationPayload(cipherText: cipherText, iv: iv, cryptoKey: aesKey)
        XCTAssertFalse(result.elementsEqual(validDecryptedNotificationPayload))
    }
}
