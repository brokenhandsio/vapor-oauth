import Foundation

public struct OAuthDeviceCode {
    public let deviceCodeID: String
    public let userCode: String
    public let clientID: String
    public let userID: String?
    public let expiryDate: Date
    public let scopes: [String]?

    public var extend: [String: Any] = [:]

    public init(
        deviceCodeID: String,
        userCode: String,
        clientID: String,
        userID: String?,
        expiryDate: Date,
        scopes: [String]?
    ) {
        self.deviceCodeID = deviceCodeID
        self.userCode = userCode
        self.clientID = clientID
        self.userID = userID
        self.expiryDate = expiryDate
        self.scopes = scopes
    }

    public var isExpired: Bool {
        return Date() > expiryDate
    }
}
