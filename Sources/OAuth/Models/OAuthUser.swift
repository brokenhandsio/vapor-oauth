import Authentication
import Core

open class OAuthUser: Authenticatable {
    public let username: String
    public let emailAddress: String?
    public let password: Bytes
    open var userID: String?
    
    public init(userID: String?, username: String, emailAddress: String?, password: Bytes) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.userID = userID
    }
}
