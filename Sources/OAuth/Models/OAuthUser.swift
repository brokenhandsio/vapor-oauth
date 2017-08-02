import Authentication
import Core

public final class OAuthUser: Authenticatable, Extendable {
    public let username: String
    public let emailAddress: String?
    public let password: Bytes
    public let userID: String?
    
    public var extend: [String: Any] = [:]
    
    public init(userID: String?, username: String, emailAddress: String?, password: Bytes) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.userID = userID
    }
}
