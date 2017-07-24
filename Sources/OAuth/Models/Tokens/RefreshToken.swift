open class RefreshToken {
    public let tokenString: String
    public let clientID: String
    public let userID: String?
    public var scopes: [String]?
    
    public init(tokenString: String, clientID: String, userID: String?, scopes: [String]? = nil) {
        self.tokenString = tokenString
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
    }
}
