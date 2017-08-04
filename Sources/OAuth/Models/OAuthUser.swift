import Authentication
import Core
import Node

public final class OAuthUser: Authenticatable, Extendable {
    public let username: String
    public let emailAddress: String?
    public let password: Bytes
    public var id: Identifier?

    public var extend: [String: Any] = [:]

    public init(id: Identifier? = nil, username: String, emailAddress: String?, password: Bytes) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.id = id
    }
}
