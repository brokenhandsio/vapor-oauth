import Crypto
import Foundation

struct PKCEValidator {
    static let supportedMethod = "S256"

    func verifyCodeVerifier(_ codeVerifier: String, matchesChallenge codeChallenge: String) -> Bool {
        let digest = SHA256.hash(data: Data(codeVerifier.utf8))

        let base64URLChallenge =
            Data(digest)
            .base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")

        return base64URLChallenge == codeChallenge
    }
}
