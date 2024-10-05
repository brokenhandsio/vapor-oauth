import Vapor

@testable import VaporOAuth

struct FakeAccessToken: AccessToken {
    let tokenString: String
    let clientID: String
    let userID: String?
    let scopes: [String]?
    let expiryTime: Date

    init(tokenString: String, clientID: String, userID: String? = nil, scopes: [String]? = nil, expiryTime: Date) {
        self.tokenString = tokenString
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
        self.expiryTime = expiryTime
    }
}
