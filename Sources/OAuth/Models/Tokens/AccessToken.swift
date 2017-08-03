import Foundation
import Core
import Node

public final class AccessToken: Extendable {
    public let tokenString: String
    public let clientID: String
    public let userID: Identifier?
    public let scopes: [String]?
    public let expiryTime: Date
    
    public var extend: [String: Any] = [:]
    
    public init(tokenString: String, clientID: String, userID: Identifier?, scopes: [String]? = nil, expiryTime: Date) {
        self.tokenString = tokenString
        self.clientID = clientID
        self.userID = userID
        self.scopes = scopes
        self.expiryTime = expiryTime
    }
}
