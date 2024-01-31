import VaporOAuth
import Foundation

class FakeCodeManager: CodeManager {

    private(set) var usedCodes: [String] = []
    var codes: [String: OAuthCode] = [:]
    var deviceCodes: [String: OAuthDeviceCode] = [:]
    var generatedCode = UUID().uuidString
    
    func getCode(_ code: String) -> OAuthCode? {
        return codes[code]
    }

    func getDeviceCode(_ deviceCode: String) -> OAuthDeviceCode? {
        return deviceCodes[deviceCode]
    }
    
    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?) throws -> String {
        let code = OAuthCode(codeID: generatedCode, clientID: clientID, redirectURI: redirectURI, userID: userID, expiryDate: Date().addingTimeInterval(60), scopes: scopes)
        codes[generatedCode] = code
        return generatedCode
    }

    func generateDeviceCode(userID: String, clientID: String, scopes: [String]?) throws -> String { // Added to generate a device code
        let deviceCode = OAuthDeviceCode(deviceCodeID: generatedCode, userCode: "USER_CODE", clientID: clientID, userID: userID, expiryDate: Date().addingTimeInterval(60), scopes: scopes)
        deviceCodes[generatedCode] = deviceCode
        return generatedCode
    }
    
    func codeUsed(_ code: OAuthCode) {
        usedCodes.append(code.codeID)
        codes.removeValue(forKey: code.codeID)
    }

    func deviceCodeUsed(_ deviceCode: OAuthDeviceCode) {
        usedCodes.append(deviceCode.deviceCodeID)
        deviceCodes.removeValue(forKey: deviceCode.deviceCodeID)
    }
}
