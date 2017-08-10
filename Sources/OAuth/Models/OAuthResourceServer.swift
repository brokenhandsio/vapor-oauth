import Authentication
import Vapor

public final class OAuthResourceServer: Extendable {
    public let username: String
    public let password: Bytes
    public var extend: [String: Any] = [:]

    static let passwordVerifier: PasswordVerifier = OAuthResourceServer.passwordHasher
    static var passwordHasher: PasswordHasherVerifier = BCryptHasher(cost: 10)

    public init(username: String, password: Bytes) {
        self.username = username
        self.password = password
    }
}

protocol PasswordHasherVerifier: PasswordVerifier, HashProtocol {}

extension BCryptHasher: PasswordHasherVerifier {}
