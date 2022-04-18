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

import AzureCommunicationCommon
import AzureCore
import CryptoKit
import Foundation

/// ChatClient class for ChatThread operations.
public class PushNotificationClient {
    // MARK: Properties

    private let credential: CommunicationTokenCredential
    private let options: AzureCommunicationChatClientOptions
    private var registrarClient: RegistrarClient?
    internal var registrationId: String
    internal var deviceRegistrationToken: String
    private var aesKey: String
    private var authKey: String
    private var previousAesKey: String
    private var previousAuthKey: String
    private var keyRotateTimeMillis: Int64
    private static let cryptoMethod: String = "0x70"
    private static let aesKeyKeychainTag: String = "aesKey"
    private static let authKeyKeychainTag: String = "authKey"
    private static let keyRotateGracePeriodMilis: Int64 = 3_600_000

    // MARK: Initializers

    internal init(
        credential: CommunicationTokenCredential,
        options: AzureCommunicationChatClientOptions
    ) {
        self.credential = credential
        self.options = options
        self.registrationId = ""
        self.deviceRegistrationToken = ""
        self.aesKey = ""
        self.authKey = ""
        self.previousAesKey = ""
        self.previousAuthKey = ""
        self.keyRotateTimeMillis = 0
    }

    internal func startPushNotifications(
        deviceRegistrationToken: String,
        completionHandler: @escaping (Result<HTTPResponse?, AzureError>) -> Void
    ) {
        self.deviceRegistrationToken = deviceRegistrationToken

        // Create RegistrarClient
        createRegistrarClient(
            credential: credential,
            options: options,
            registrationId: registrationId,
            completionHandler: { result in
                switch result {
                case let .success(createdRegistrarClient):
                    self.registrarClient = createdRegistrarClient

                    // Get the latest cryptoKey and AuthKey
                    do {
                        try self.refreshEncryptionKeys()
                    } catch {
                        completionHandler(.failure(AzureError.client("Failed to start push notifications", error)))
                        return
                    }

                    print("Print aes key:", self.aesKey)
                    print("Print auth key:", self.authKey)
                    print("Print previousAESKey:", self.previousAesKey)
                    print("Print previousAUTHKey:", self.previousAuthKey)

                    // Create RegistrarClientDescription (It should match valid APNS templates)
                    let clientDescription = RegistrarClientDescription(
                        appId: RegistrarSettings.appId,
                        languageId: RegistrarSettings.languageId,
                        platform: RegistrarSettings.platform,
                        platformUIVersion: RegistrarSettings.platformUIVersion,
                        templateKey: RegistrarSettings.templateKey,
                        aesKey: self.aesKey,
                        authKey: self.authKey,
                        cryptoMethod: PushNotificationClient.cryptoMethod
                    )

                    // Create RegistrarTransportSettings (Path is device token)
                    let transport = RegistrarTransportSettings(
                        ttl: RegistrarSettings.ttl,
                        path: self.deviceRegistrationToken,
                        context: RegistrarSettings.context
                    )

                    // Register for push notifications
                    guard let registrarClient = self.registrarClient else {
                        completionHandler(.failure(AzureError.client("RegistrarClient is nil.")))
                        return
                    }

                    registrarClient.setRegistration(with: clientDescription, for: [transport]) { result in
                        switch result {
                        case let .success(response):
                            completionHandler(.success(response))
                        case let .failure(error):
                            self.options.logger
                                .error("Failed to set registration with error: \(error.localizedDescription)")
                            completionHandler(.failure(
                                AzureError
                                    .client("Failed to set registration with error", error)
                            ))
                        }
                    }
                case let .failure(error):
                    completionHandler(.failure(AzureError.client("Failed to initialize the RegistrarClient.", error)))
                }
            }
        )
    }

    internal func stopPushNotifications(
        completionHandler: @escaping (Result<HTTPResponse?, AzureError>) -> Void
    ) {
        // Report an error if registrarClient doesn't exist
        if registrarClient == nil {
            completionHandler(.failure(
                AzureError
                    .client(
                        "RegistrarClient is not initialized, cannot stop push notificaitons. Ensure startNotifications() is called first."
                    )
            ))
        } else {
            // Unregister for Push Notifications
            registrarClient!.deleteRegistration { result in
                switch result {
                case let .success(response):
                    completionHandler(.success(response))
                case let .failure(error):
                    self.options.logger
                        .error("Failed to stop push notifications with error: \(error.localizedDescription)")
                    completionHandler(.failure(AzureError.client("Failed to stop push notifications", error)))
                }
            }
        }
    }

    /*
     internal func refreshEncryptionKeys() throws {
         do {
             let oldAESKey = try retrieveSymmetricKey(withKeychainTag: PushNotificationClient.aesKeyKeychainTag)
             let oldAUTHKey = try retrieveSymmetricKey(withKeychainTag: PushNotificationClient.authKeyKeychainTag)

             // Update previous keys with current keys if necessary
             if oldAESKey != nil, oldAUTHKey != nil {
                 previousAesKey = oldAESKey!.serialize()
                 previousAuthKey = oldAUTHKey!.serialize()
             }

             // Update current keys in the keychain
             try deleteSymmetricKey(withKeychainTag: PushNotificationClient.aesKeyKeychainTag)
             try deleteSymmetricKey(withKeychainTag: PushNotificationClient.authKeyKeychainTag)

             try generateAndStoreSymmetricKey(withKeychainTag: PushNotificationClient.aesKeyKeychainTag)
             try generateAndStoreSymmetricKey(withKeychainTag: PushNotificationClient.authKeyKeychainTag)
             keyRotateTimeMillis = Date().millisecondsSince1970

             // Retrieve current keys from the keychain
             guard let AESKey = try retrieveSymmetricKey(withKeychainTag: PushNotificationClient.aesKeyKeychainTag),
                   let AUTHKey = try retrieveSymmetricKey(withKeychainTag: PushNotificationClient.authKeyKeychainTag)
             else {
                 throw AzureError.client("Failed to retrieve current encryption keys from the keychain")
             }

             aesKey = AESKey.serialize()
             authKey = AUTHKey.serialize()

         } catch {
             throw AzureError.client("Error in refreshing encryption keys: \(error)")
         }
     }
      */

    internal func refreshEncryptionKeys() throws {
        previousAesKey = aesKey
        previousAuthKey = authKey

        aesKey = SymmetricKey(size: .bits256).serialize()
        authKey = SymmetricKey(size: .bits256).serialize()

        keyRotateTimeMillis = Date().millisecondsSince1970
    }

    internal func decryptPayload(encryptedStr: String?) throws -> String {
        do {
            // 1.Retrieve encryption keys from keychain

            /*
             guard let AESKey = try retrieveSymmetricKey(withKeychainTag: PushNotificationClient.aesKeyKeychainTag)
             else {
                 throw AzureError.client("Failed to retrieve the AES key from KeyChain")
             }

             guard let AUTHKey = try retrieveSymmetricKey(withKeychainTag: PushNotificationClient.authKeyKeychainTag)
             else {
                 throw AzureError.client("Failed to retrieve the AUTH key from KeyChain")
             }

             aesKey = AESKey.serialize()
             authKey = AUTHKey.serialize()
              */

            print("Print aes key:", aesKey)
            print("Print auth key:", authKey)
            print("Print previousAESKey:", previousAesKey)
            print("Print previousAUTHKey:", previousAuthKey)

            // 2.Decode the Base64 input string into [UInt8]
            guard let encryptedStr = encryptedStr else {
                print("Failed to retrieve the encrypted message.")
                throw AzureError.client("The message payload is empty.")
            }

            guard let decodedData = Data(base64Encoded: encryptedStr) else {
                throw AzureError.client("Failed to convert Base64 encoded message payload into Data format.")
            }

            let encryptedBytes = Array(decodedData)

            // 3.Split [UInt8] into different blocks
            let cipherMode: [UInt8] = CryptoUtils.extractCipherMode(result: encryptedBytes)
            let iv: [UInt8] = CryptoUtils.extractInitializationVector(result: encryptedBytes)
            let cipherText: [UInt8] = CryptoUtils.extractCipherText(result: encryptedBytes)
            let hmac: [UInt8] = CryptoUtils.extractHmac(result: encryptedBytes)
            let cipherModeIVCipherText: [UInt8] = CryptoUtils.extractCipherModeIVCipherText(result: encryptedBytes)

            // 4.If the computed signature matched the included signature, decrypt the string
            let testHMACResult = try verifyEncryptedPayload(
                cipherModeIVCipherText: cipherModeIVCipherText,
                authKey: authKey,
                actualHmac: hmac
            )
            print("Print HMACResult:", testHMACResult)

            if testHMACResult {
                let testDecryptedString = decryptPushNotificationPayload(
                    cipherText: cipherText,
                    iv: iv,
                    cryptoKey: aesKey
                )
                print("Print DecryptedString:", testDecryptedString)
                return testDecryptedString
            }

            /*
             if try verifyEncryptedPayload(cipherModeIVCipherText: cipherModeIVCipherText, authKey: self.authKey, actualHmac: hmac){
                 return decryptPushNotificationPayload(cipherText: cipherText, iv: iv, cryptoKey: self.aesKey)
             }
             */

            // 5. Try old key if the new key failed to decrypt the payload.
            // Reason: When client has registered a new key, because of eventual consistency, latencies and concurrency,
            // the old key can still be used by server side for some notifications
            let canPreviousAuthKeyVerifyPayload = try verifyEncryptedPayload(
                cipherModeIVCipherText: cipherModeIVCipherText,
                authKey: previousAuthKey,
                actualHmac: hmac
            )

            if canPreviousAuthKeyVerifyPayload, inKeyRotationGracePeriod() {
                let payloadDecryptedByOldKeys = decryptPushNotificationPayload(
                    cipherText: cipherText,
                    iv: iv,
                    cryptoKey: previousAesKey
                )
                print("Print DecryptedString:", payloadDecryptedByOldKeys)
                return payloadDecryptedByOldKeys
            }

            // 6. Failed to decrypt the push notification when computed signature does not match the included signature - it can not be trusted
            throw AzureError
                .client(
                    "Invalid encrypted push notification payload. The computed signature does not match the included signature."
                )

        } catch {
            throw AzureError.client("error in decrypting the payload: \(error)")
        }
    }

    internal func inKeyRotationGracePeriod() -> Bool {
        if previousAesKey != "" {
            let currentTimeMillis = Date().millisecondsSince1970
            if currentTimeMillis - keyRotateTimeMillis
                <= PushNotificationClient.keyRotateGracePeriodMilis {
                return true
            }
        }
        return false
    }
}
