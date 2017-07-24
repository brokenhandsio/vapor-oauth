import Foundation

open class AccessToken {
    public let tokenString: String
    public let clientID: String
    public let userID: String?
    public let scopes: [String]?
    public let expiryTime: Date
    
    public init(tokenString: String, clientID: String, userID: String?, scopes: [String]? = nil, expiryTime: Date) {
        self.tokenString = tokenString
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
        self.expiryTime = expiryTime
    }
}
