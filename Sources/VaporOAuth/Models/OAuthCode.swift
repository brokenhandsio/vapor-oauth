import Foundation

public final class OAuthCode {
    public let codeID: String
    public let clientID: String
    public let redirectURI: String
    public let userID: String
    public let expiryDate: Date
    public let scopes: [String]?

    public var extend: [String: Any] = [:]

    public init(
        codeID: String,
        clientID: String,
        redirectURI: String,
        userID: String,
        expiryDate: Date,
        scopes: [String]?
    ) {
        self.codeID = codeID
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.userID = userID
        self.expiryDate = expiryDate
        self.scopes = scopes
    }
}
