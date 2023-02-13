import Vapor

public final class OAuthResourceServer: Extendable {
    public let username: String
    public let password: String
    public var extend: Vapor.Extend = .init()

    public init(username: String, password: String) {
        self.username = username
        self.password = password
    }
}
