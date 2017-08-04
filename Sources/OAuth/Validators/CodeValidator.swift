import Foundation

struct CodeValidator {
    func validateCode(_ code: OAuthCode, clientID: String, redirectURI: String) -> Bool {
        guard code.clientID == clientID else {
            return false
        }

        guard code.expiryDate >= Date() else {
            return false
        }

        guard code.redirectURI == redirectURI else {
            return false
        }

        return true
    }
}
