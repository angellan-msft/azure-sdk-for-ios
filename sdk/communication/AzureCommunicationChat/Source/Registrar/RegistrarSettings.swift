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

import Foundation

internal enum RegistrarSettings {
    // Node id is unused but we are required to send it
    static let nodeId = ""

    // ClientDescription Settings
    static let appId = "AcsIos"
    static let languageId = ""
    static let platform = "iOS"
    static let platformUIVersion = "3619/0.0.0.0/"
    static let templateKey = "AcsIos.AcsNotify_Chat_4.0"

    // Transport Settings
    static let pushNotificationTransport = "APNS"
    // Max TTL is 180 days
    static let ttl = 15_552_000
    static let context = ""
}

internal enum RegistrarHeader: String {
    /// Content-type header.
    case contentType = "Content-Type"
    /// Skype token for authentication.
    case skypeTokenHeader = "X-Skypetoken"
}

internal enum RegistrarMimeType: String {
    case json = "application/json"
}
