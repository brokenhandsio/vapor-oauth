import Foundation
import Crypto // Import SwiftCrypto for SHA-256

struct CodeValidator {
    func validateCode(_ code: OAuthCode, clientID: String, redirectURI: String, codeVerifier: String?) -> Bool {
        guard code.clientID == clientID else {
            return false
        }

        guard code.expiryDate >= Date() else {
            return false
        }

        guard code.redirectURI == redirectURI else {
            return false
        }

        // Optional PKCE validation
        if let codeChallenge = code.codeChallenge, let codeChallengeMethod = code.codeChallengeMethod, let verifier = codeVerifier {
            switch codeChallengeMethod {
            case "S256":
                // Transform the codeVerifier using SHA256 and base64-url-encode it
                guard let verifierData = verifier.data(using: .utf8) else { return false }
                let verifierHash = SHA256.hash(data: verifierData)
                let encodedVerifier = Data(verifierHash).base64URLEncodedString()

                return codeChallenge == encodedVerifier
            default:
                // If the code challenge method is unknown, fail the validation
                return false
            }
        }

        // If no PKCE was used (codeVerifier is nil), skip PKCE validation
        return true
    }
}

// Helper extension for base64 URL encoding
extension Data {
    func base64URLEncodedString() -> String {
        return self.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
