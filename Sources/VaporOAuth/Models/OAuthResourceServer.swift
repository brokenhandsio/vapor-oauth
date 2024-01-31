import Vapor

public struct OAuthResourceServer {
    public let username: String
    public let password: String
    public var extend: [String: String]?

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}