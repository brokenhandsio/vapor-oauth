import JWTKit
import Vapor

public protocol IDToken {
    var tokenString: String { get set }
    var issuer: String { get set }
    var subject: String { get set }
    var audience: [String] { get set }
    var expiration: Date { get set }
    var issuedAt: Date { get set }
    var nonce: String? { get set }
    var authTime: Date? { get set }
    // Additional claims can be added as needed
}
