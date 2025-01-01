import Vapor

@testable import VaporOAuth

public struct FakeRefreshToken: RefreshToken {
    public var tokenString: String
    public var clientID: String
    public var userID: String?
    public var scopes: [String]?
}
