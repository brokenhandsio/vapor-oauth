import Authentication
import Vapor

public final class OAuthResourceServer: Extendable {
    public let username: String
    public let password: Bytes
    public var extend: [String: Any] = [:]

    public init(username: String, password: Bytes) {
        self.username = username
        self.password = password
    }
}
