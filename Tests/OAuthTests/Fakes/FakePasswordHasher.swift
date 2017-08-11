import Vapor
@testable import OAuth

struct FakePasswordHasher: PasswordHasherVerifier {
    func verify(password: Bytes, matches hash: Bytes) throws -> Bool {
        return password == hash
    }
    
    func make(_ message: Bytes) throws -> Bytes {
        return message
    }
    
    func check(_ message: Bytes, matchesHash: Bytes) throws -> Bool {
        return message == matchesHash
    }
}
