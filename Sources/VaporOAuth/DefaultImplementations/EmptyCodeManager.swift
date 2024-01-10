public struct EmptyCodeManager: CodeManager {
    public init() {}
    
    public func getCode(_ code: String) -> OAuthCode? {
        return nil
    }
    
    public func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?,
        nonce: String?
    ) async throws -> String {
        return ""
    }
    
    public func codeUsed(_ code: OAuthCode) {}
    
    public func getDeviceCode(_ deviceCode: String) -> OAuthDeviceCode? {
        return nil
    }
    
    public func generateDeviceCode(userID: String, clientID: String, scopes: [String]?) async throws -> String {
        return ""
    }
    
    public func deviceCodeUsed(_ deviceCode: OAuthDeviceCode) {}
}
