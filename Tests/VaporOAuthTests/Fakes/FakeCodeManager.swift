import VaporOAuth
import Foundation

class FakeCodeManager: CodeManager {

    private(set) var usedCodes: [String] = []
    var codes: [String: OAuthCode] = [:]
    var generatedCode = UUID().uuidString
    
    func getCode(_ code: String) -> OAuthCode? {
        return codes[code]
    }
    
    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?) throws -> String {
        let code = OAuthCode(codeID: generatedCode, clientID: clientID, redirectURI: redirectURI, userID: userID, expiryDate: Date().addingTimeInterval(60), scopes: scopes)
        codes[generatedCode] = code
        return generatedCode
    }
    
    func codeUsed(_ code: OAuthCode) {
        usedCodes.append(code.codeID)
        codes.removeValue(forKey: code.codeID)
    }
}
