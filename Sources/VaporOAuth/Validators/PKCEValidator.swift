import Foundation
import Crypto

struct PKCEValidator {
    
    static func validate(codeChallenge: String, verifier: String?, method: String?) -> Bool {
        guard let verifier = verifier else {
            // Fail validation if codeVerifier is not provided
            return false
        }
        
        guard let method = method else {
            // Default to plain if no method is provided
            return codeChallenge == verifier
        }
        
        switch method {
        case "S256":
            return validateS256(codeChallenge: codeChallenge, verifier: verifier)
        case "plain":
            return codeChallenge == verifier
        default:
            // Unsupported code challenge method
            return false
        }
    }
    
    private static func validateS256(codeChallenge: String, verifier: String) -> Bool {
        guard let verifierData = verifier.data(using: .utf8) else { return false }
        let hashedVerifier = SHA256.hash(data: verifierData)
        let base64UrlEncodedHash = Data(hashedVerifier).base64URLEncodedString()
        return codeChallenge == base64UrlEncodedHash
    }
}
