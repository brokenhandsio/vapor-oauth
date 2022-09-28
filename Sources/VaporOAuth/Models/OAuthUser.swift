import Vapor

public final class OAuthUser: Authenticatable, Extendable {
    public let username: String
    public let emailAddress: String?
    public var password: ByteBuffer
    // swiftlint:disable:next identifier_name
    public var id: String?

    public var extend: Extend = .init()

    public init(userID: String? = nil, username: String, emailAddress: String?, password: ByteBuffer) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.id = userID
    }
}
