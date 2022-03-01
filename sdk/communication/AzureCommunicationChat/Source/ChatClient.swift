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
import Foundation

/// ChatClient class for ChatThread operations.
public class ChatClient {
    // MARK: Properties

    private let endpoint: String
    private let credential: CommunicationTokenCredential
    private let options: AzureCommunicationChatClientOptions
    private var registrarClient: RegistrarClient?
    internal var registrationId: String
    private let service: Chat
    private var signalingClient: CommunicationSignalingClient?
    private var signalingClientStarted: Bool = false
    private var pushNotificationsStarted: Bool = false

    // MARK: Initializers

    /// Create a ChatClient.
    /// - Parameters:
    ///   - endpoint: The Communication Services endpoint.
    ///   - credential: The user credential.
    ///   - userOptions: Options used to configure the client.
    public init(
        endpoint: String,
        credential: CommunicationTokenCredential,
        withOptions userOptions: AzureCommunicationChatClientOptions
    ) throws {
        self.endpoint = endpoint
        self.credential = credential
        self.registrationId = UUID().uuidString

        guard let endpointUrl = URL(string: endpoint) else {
            throw AzureError.client("Unable to form base URL.")
        }

        // If applicationId is not provided bundle identifier will be used
        // Instead set the default application id to be an empty string
        var options: AzureCommunicationChatClientOptions = userOptions
        if userOptions.telemetryOptions.applicationId == nil {
            let apiVersion = AzureCommunicationChatClientOptions.ApiVersion(userOptions.apiVersion)
            let telemetryOptions = TelemetryOptions(
                telemetryDisabled: userOptions.telemetryOptions.telemetryDisabled,
                applicationId: ""
            )

            options = AzureCommunicationChatClientOptions(
                apiVersion: apiVersion,
                logger: userOptions.logger,
                telemetryOptions: telemetryOptions,
                transportOptions: userOptions.transportOptions,
                dispatchQueue: userOptions.dispatchQueue,
                signalingErrorHandler: userOptions.signalingErrorHandler
            )
        }

        self.options = options

        // Internal options do not use the CommunicationSignalingErrorHandler
        let internalOptions = AzureCommunicationChatClientOptionsInternal(
            apiVersion: AzureCommunicationChatClientOptionsInternal.ApiVersion(options.apiVersion),
            logger: options.logger,
            telemetryOptions: options.telemetryOptions,
            transportOptions: options.transportOptions,
            dispatchQueue: options.dispatchQueue
        )

        let communicationCredential = TokenCredentialAdapter(credential)
        let authPolicy = BearerTokenCredentialPolicy(credential: communicationCredential, scopes: [])

        let client = try ChatClientInternal(
            endpoint: endpointUrl,
            authPolicy: authPolicy,
            withOptions: internalOptions
        )

        self.service = client.chat
    }

    // MARK: Private Methods

    /// Converts [ChatParticipant] to [ChatParticipantInternal] for internal use.
    /// - Parameter chatParticipants: The array of ChatParticipants.
    /// - Returns: An array of ChatParticipants.
    private func convert(chatParticipants: [ChatParticipant]?) throws -> [ChatParticipantInternal]? {
        guard let participants = chatParticipants else {
            return nil
        }

        return try participants.map { participant -> ChatParticipantInternal in
            let identifierModel = try IdentifierSerializer.serialize(identifier: participant.id)
            return ChatParticipantInternal(
                communicationIdentifier: identifierModel,
                displayName: participant.displayName,
                shareHistoryTime: participant.shareHistoryTime
            )
        }
    }

    // MARK: Public Methods

    /// Create a ChatThreadClient for the ChatThread with id threadId.
    /// - Parameters:
    ///   - threadId: The threadId.
    public func createClient(forThread threadId: String) throws -> ChatThreadClient {
        return try ChatThreadClient(
            endpoint: endpoint,
            credential: credential,
            threadId: threadId,
            withOptions: options
        )
    }

    /// Create a new ChatThread.
    /// - Parameters:
    ///   - thread: Request for creating a chat thread with the topic and optional members to add.
    ///   - options: Create chat thread options.
    ///   - completionHandler: A completion handler that receives a ChatThreadClient on success.
    public func create(
        thread: CreateChatThreadRequest,
        withOptions options: CreateChatThreadOptions? = nil,
        completionHandler: @escaping HTTPResultHandler<CreateChatThreadResult>
    ) {
        // Set the repeatabilityRequestId if it is not provided
        let requestOptions = ((options?.repeatabilityRequestId) != nil) ? options : CreateChatThreadOptions(
            repeatabilityRequestId: UUID().uuidString,
            clientRequestId: options?.clientRequestId,
            cancellationToken: options?.cancellationToken,
            dispatchQueue: options?.dispatchQueue,
            context: options?.context
        )

        do {
            // Convert ChatParticipant to ChatParticipantInternal
            let participants = try convert(chatParticipants: thread.participants)

            // Convert to CreateChatThreadRequestInternal
            let request = CreateChatThreadRequestInternal(
                topic: thread.topic,
                participants: participants
            )

            service.create(chatThread: request, withOptions: requestOptions) { result, httpResponse in
                switch result {
                case let .success(chatThreadResult):
                    do {
                        let threadResult = try CreateChatThreadResult(from: chatThreadResult)
                        completionHandler(.success(threadResult), httpResponse)
                    } catch {
                        let azureError = AzureError.client(error.localizedDescription, error)
                        completionHandler(.failure(azureError), httpResponse)
                    }

                case let .failure(error):
                    completionHandler(.failure(error), httpResponse)
                }
            }
        } catch {
            // Return error from converting participants
            let azureError = AzureError.client("Failed to construct create thread request.", error)
            completionHandler(.failure(azureError), nil)
        }
    }

    /// Gets the list of ChatThreads for the user.
    /// - Parameters:
    ///   - options: List chat threads options.
    ///   - completionHandler: A completion handler that receives the list of chat thread items on success.
    public func listThreads(
        withOptions options: ListChatThreadsOptions? = nil,
        completionHandler: @escaping HTTPResultHandler<PagedCollection<ChatThreadItem>>
    ) {
        service.listChatThreads(withOptions: options) { result, httpResponse in
            switch result {
            case let .success(chatThreads):
                completionHandler(.success(chatThreads), httpResponse)

            case let .failure(error):
                completionHandler(.failure(error), httpResponse)
            }
        }
    }

    /// Delete the ChatThread with id chatThreadId.
    /// - Parameters:
    ///   - threadId: The chat thread id.
    ///   - options: Delete chat thread options.
    ///   - completionHandler: A completion handler.
    public func delete(
        thread threadId: String,
        withOptions options: DeleteChatThreadOptions? = nil,
        completionHandler: @escaping HTTPResultHandler<Void>
    ) {
        service.deleteChatThread(chatThreadId: threadId, withOptions: options) { result, httpResponse in
            switch result {
            case .success:
                completionHandler(.success(()), httpResponse)

            case let .failure(error):
                completionHandler(.failure(error), httpResponse)
            }
        }
    }

    /// Start receiving realtime notifications.
    /// Call this function before subscribing to any event.
    /// - Parameter completionHandler: Called when starting notifications has completed.
    public func startRealTimeNotifications(completionHandler: @escaping (Result<Void, AzureError>) -> Void) {
        guard signalingClientStarted == false else {
            completionHandler(.failure(AzureError.client("Realtime notifications have already started.")))
            return
        }

        // Retrieve the access token
        credential.token { accessToken, error in
            do {
                guard let token = accessToken?.token else {
                    throw AzureError.client("Failed to get token from credential.", error)
                }

                let tokenProvider = CommunicationSkypeTokenProvider(
                    token: token,
                    credential: self.credential,
                    tokenRefreshHandler: { stopSignalingClient, error in
                        // Unable to refresh the token, stop the connection
                        if stopSignalingClient {
                            self.signalingClient?.stop()
                            self.signalingClientStarted = false
                            self.options
                                .signalingErrorHandler?(
                                    .failedToRefreshToken(
                                        "Unable to get valid token for realtime-notifications, stopping notifications."
                                    )
                                )
                            return
                        }

                        // Token is invalid, attempting to refresh token
                        self.options.logger.error("Failed to get valid token. \(error ?? "")")
                        self.options.logger.warning("Attempting to refresh token for realtime-notifications.")
                    }
                )

                // Initialize the signaling client
                self.signalingClient = try CommunicationSignalingClient(
                    communicationSkypeTokenProvider: tokenProvider,
                    logger: self.options.logger
                )

                // After successful initialization, start notifications
                self.signalingClientStarted = true
                self.signalingClient!.start()

                completionHandler(.success(()))
            } catch {
                let azureError = AzureError.client("Failed to start realtime notifications.", error)
                completionHandler(.failure(azureError))
            }
        }
    }

    /// Stop receiving realtime notifications.
    /// This function would unsubscribe to all events.
    public func stopRealTimeNotifications() {
        if signalingClient == nil {
            options.logger.warning("Signaling client is not initialized, realtime notifications have not been started.")
            return
        }

        signalingClientStarted = false
        signalingClient!.stop()
    }

    /// Subscribe to chat events.
    /// - Parameters:
    ///   - event: The chat event to subsribe to.
    ///   - handler: The handler for the chat event.
    public func register(
        event: ChatEventId,
        handler: @escaping TrouterEventHandler
    ) {
        if signalingClient == nil {
            options.logger
                .warning(
                    "Signaling client is not initialized, cannot register handler. Ensure startRealtimeNotifications() is called first."
                )
            return
        }

        signalingClient!.on(event: event, handler: handler)
    }

    /// Unsubscribe to chat events.
    /// - Parameters:
    ///   - event: The chat event to unsubsribe from.
    public func unregister(
        event: ChatEventId
    ) {
        if signalingClient == nil {
            options.logger
                .warning(
                    "Signaling client is not initialized, cannot unregister handler. Ensure startRealtimeNotifications() is called first."
                )
            return
        }

        signalingClient!.off(event: event)
    }

    /// Start push notifications. Receiving of notifications can be expected ~1 second after successfully registering.
    /// - Parameters:
    ///   - deviceToken: APNS push token.
    ///   - completionHandler: Success indicates request to register for notifications has been received.
    public func startPushNotifications(
        deviceToken: String,
        completionHandler: @escaping (Result<HTTPResponse?, AzureError>) -> Void
    ) {
        guard !pushNotificationsStarted else {
            completionHandler(.failure(AzureError.client("Push notifications already started.")))
            return
        }

        // Internal options do not use the CommunicationSignalingErrorHandler
        let internalOptions = AzureCommunicationChatClientOptionsInternal(
            apiVersion: AzureCommunicationChatClientOptionsInternal.ApiVersion(options.apiVersion),
            logger: options.logger,
            telemetryOptions: options.telemetryOptions,
            transportOptions: options.transportOptions,
            dispatchQueue: options.dispatchQueue
        )

        let communicationCredential = TokenCredentialAdapter(credential)
        let authPolicy = BearerTokenCredentialPolicy(credential: communicationCredential, scopes: [])

        // Initialize the RegistrarClient
        guard let registrarClient = try? RegistrarClient(
            endpoint: RegistrarSettings.endpoint,
            credential: credential,
            registrationId: registrationId,
            authPolicy: authPolicy,
            withOptions: internalOptions
        ) else {
            completionHandler(.failure(AzureError.client("Failed to enable push notifications.")))
            return
        }

        // Client description should match valid APNS templates
        let clientDescription = RegistrarClientDescription(
            appId: RegistrarSettings.appId,
            languageId: RegistrarSettings.languageId,
            platform: RegistrarSettings.platform,
            platformUIVersion: RegistrarSettings.platformUIVersion,
            templateKey: RegistrarSettings.templateKey
        )

        // Path is device token
        let transport = RegistrarTransportSettings(
            ttl: RegistrarSettings.ttl,
            path: deviceToken,
            context: RegistrarSettings.context
        )

        // Register for push notifications
        registrarClient.setRegistration(with: clientDescription, for: [transport]) { result in
            switch result {
            case let .success(response):
                self.pushNotificationsStarted = true
                completionHandler(.success(response))
            case let .failure(error):
                self.options.logger
                    .error("Failed to start push notifications with error: \(error.localizedDescription)")
                completionHandler(.failure(AzureError.client("Failed to start push notifications", error)))
            }
        }
    }

    /// Stop push notifications.
    /// - Parameter completionHandler: Success indicates push notifications have been stopped.
    public func stopPushNotifications(
        completionHandler: @escaping (Result<HTTPResponse?, AzureError>) -> Void
    ) {
        guard pushNotificationsStarted else {
            completionHandler(.failure(AzureError.client("Push notifications are not enabled.")))
            return
        }

        // Recreate the registrarClient if it doesn't exist
        if registrarClient == nil {
            // Internal options do not use the CommunicationSignalingErrorHandler
            let internalOptions = AzureCommunicationChatClientOptionsInternal(
                apiVersion: AzureCommunicationChatClientOptionsInternal.ApiVersion(options.apiVersion),
                logger: options.logger,
                telemetryOptions: options.telemetryOptions,
                transportOptions: options.transportOptions,
                dispatchQueue: options.dispatchQueue
            )

            let communicationCredential = TokenCredentialAdapter(credential)
            let authPolicy = BearerTokenCredentialPolicy(credential: communicationCredential, scopes: [])

            // Initialize the RegistrarClient
            guard let tempRegistrarClient = try? RegistrarClient(
                endpoint: RegistrarSettings.endpoint,
                credential: credential,
                registrationId: registrationId,
                authPolicy: authPolicy,
                withOptions: internalOptions
            ) else {
                completionHandler(.failure(
                    AzureError
                        .client("Failed to stop push notifications. Fail to find or create registrarClient.")
                ))
                return
            }

            registrarClient = tempRegistrarClient
        }

        registrarClient!.deleteRegistration { result in
            switch result {
            case let .success(response):
                self.pushNotificationsStarted = false
                completionHandler(.success(response))
            case let .failure(error):
                self.options.logger.error("Failed to stop push notifications with error: \(error.localizedDescription)")
                completionHandler(.failure(AzureError.client("Failed to stop push notifications", error)))
            }
        }
    }

    /// Handle the data payload for an incoming push notification.
    /// - Parameters:
    ///   - notification: The APNS push notification.
    ///   - completionHandler: Receives the PushNotificationEvent from the push notification payload.
    public func handlePush(
        notification: [AnyHashable: Any],
        completionHandler: PushNotificationEventHandler
    ) {
        guard let payload = notification["data"] as? [String: AnyObject] else {
            options.logger.error("Push notification does not contain data payload.")
            completionHandler(nil, AzureError.client("Push notification does not contain data payload."))
            return
        }

        do {
            let data = try JSONSerialization.data(withJSONObject: payload)

            // Determine the event type from the eventId
            let basePayload = try JSONDecoder().decode(BasePayload.self, from: data)
            let chatEventId = try ChatEventId(forCode: basePayload.eventId)
            let chatEvent = try PushNotificationEvent(chatEventId: chatEventId, from: data)

            completionHandler(chatEvent, nil)
        } catch {
            options.logger.error("Failed to handle push notification: \(error.localizedDescription)")
            completionHandler(nil, error)
        }
    }
}
