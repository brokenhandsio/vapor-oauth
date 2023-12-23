import VaporOAuth

class StubCodeManager: CodeManager {
    
    var codeToReturn = "ABCDEFHIJKLMNO"
    
    // Updated to include PKCE parameters
    func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?
    ) async throws -> String {
        return codeToReturn
    }
    
    func getCode(_ code: String) -> OAuthCode? {
        return nil
    }
    
    func codeUsed(_ code: OAuthCode) {
        
    }
    
    func getDeviceCode(_ deviceCode: String) -> OAuthDeviceCode? {
        
        return nil
    }
    
    func generateDeviceCode(userID: String, clientID: String, scopes: [String]?) throws -> String {
        
        return "DEVICE_CODE"
    }
    
    func deviceCodeUsed(_ deviceCode: OAuthDeviceCode) {
        
    }
    
    
}
