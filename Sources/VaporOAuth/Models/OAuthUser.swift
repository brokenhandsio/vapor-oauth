import Authentication
import Core
import Node

public final class OAuthUser: Authenticatable, Extendable {
    public let username: String
    public let emailAddress: String?
    public var password: Bytes
    // swiftlint:disable:next identifier_name
    public var id: Identifier?

    public var extend: [String: Any] = [:]

    public init(userID: Identifier? = nil, username: String, emailAddress: String?, password: Bytes) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.id = userID
    }
}
