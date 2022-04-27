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
import UIKit
import UserNotifications
import AzureCommunicationChat
import AzureCommunicationCommon
 
@main
class AppDelegate: UIResponder, UIApplicationDelegate {
 
    let token = ""
    let endpoint = "https://chat-int-test.int.communication.azure.net"
    private var chatClient: ChatClient?
    
    // MARK: App Launch
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        do{
            let credential = try CommunicationTokenCredential(token: self.token)
            let options = AzureCommunicationChatClientOptions()
            chatClient = try ChatClient(endpoint: self.endpoint, credential: credential, withOptions: options)
            // Override point for customization after application launch.
            registerForPushNotifications()
            // Check if launched from notification
            let notificationOption = launchOptions?[.remoteNotification]
            // 1
            if let notification = notificationOption as? [String: AnyObject], let aps = notification["aps"] as? [String: AnyObject] {
                print("received notification")
                print(aps)
                print(notification)
            }
            return true
        } catch {
            print("Failed to initialize chat client")
            return false
        }
    }
 
    // MARK: UISceneSession Lifecycle
    func application(_ application: UIApplication, configurationForConnecting connectingSceneSession: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        // Called when a new scene session is being created.
        // Use this method to select a configuration to create the new scene with.
        return UISceneConfiguration(name: "Default Configuration", sessionRole: connectingSceneSession.role)
    }
 
    func application(_ application: UIApplication, didDiscardSceneSessions sceneSessions: Set<UISceneSession>) {
        // Called when the user discards a scene session.
        // If any sessions were discarded while the application was not running, this will be called shortly after application:didFinishLaunchingWithOptions.
        // Use this method to release any resources that were specific to the discarded scenes, as they will not return.
    }
 
    // MARK: Register for Push Notifications after the launch of App
    func registerForPushNotifications() {
    // If you want your app’s remote notifications to display alerts, play sounds, or perform other user-facing actions, you must request authorization to do so using the requestAuthorization(options:completionHandler:) method of UNUserNotificationCenter. If you do not request and receive authorization for your app's interactions, the system delivers all remote notifications to your app silently.
        UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge]) { [weak self] granted, _ in
            print("Permission granted: \(granted)")
            guard granted else { return }
            self?.getNotificationSettings()
        }
    }
 
    func getNotificationSettings() {
        UNUserNotificationCenter.current().getNotificationSettings { settings in
            print("Notification settings: \(settings)")
            guard settings.authorizationStatus == .authorized else { return }
            DispatchQueue.main.async {
    // Call this method to initiate the registration process with Apple Push Notification service. If registration succeeds, the app calls your app delegate object’s application(_:didRegisterForRemoteNotificationsWithDeviceToken:) method and passes it a device token.You should pass this token along to the server you use to generate remote notifications for the device. If registration fails, the app calls its app delegate’s application(_:didFailToRegisterForRemoteNotificationsWithError:) method instead.
                UIApplication.shared.registerForRemoteNotifications()
            }
        }
    }
 
    // MARK: Tells the delegate that the app successfully registered with Apple Push Notification service
    func application(
    _ application: UIApplication,
    
    //A globally unique token that identifies this device to APNs. Send this token to the server that you use to generate remote notifications. Your server must pass this token unmodified back to APNs when sending those remote notifications.
    didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    
    ) {
        let tokenParts = deviceToken.map { data in String(format: "%02.2hhx", data) }
        let token = tokenParts.joined()
        print("Device Token: \(token)")
        UserDefaults.standard.set(token, forKey: "APNSToken")
        
        // Start push notifications
        guard let apnsToken = UserDefaults.standard.string(forKey: "APNSToken") else {
            print("Failed to get APNS token")
            return
        }
 
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .background).async { [weak self] in
            guard let self = self else { return }
            guard let chatClient = self.chatClient else { return }
            chatClient.startPushNotifications(deviceToken: apnsToken) { result in
                switch result {
                case .success:
                    print("Started Push Notifications")
                case let .failure(error):
                    print("Failed To Start Push Notifications: \(error)")
                }
                semaphore.signal()
            }
            semaphore.wait()
        }
    }
    
    // MARK: Tells the delegate when Apple Push Notification service cannot successfully complete the registration process.
    func application(
    _ application: UIApplication,
    didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        print("Failed to register: \(error)")
    }
}

