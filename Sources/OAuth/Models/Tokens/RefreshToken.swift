import Core

public final class RefreshToken: Extendable {
    public let tokenString: String
    public let clientID: String
    public let userID: String?
    public var scopes: [String]?
    
    public var extend: [String: Any] = [:]
    
    public init(tokenString: String, clientID: String, userID: String?, scopes: [String]? = nil) {
        self.tokenString = tokenString
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
    }
}
