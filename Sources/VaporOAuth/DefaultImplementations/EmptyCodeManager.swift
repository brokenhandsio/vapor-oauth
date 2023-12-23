public struct EmptyCodeManager: CodeManager {
    public init() {}

    public func getCode(_ code: String) -> OAuthCode? {
        return nil
    }

    // Updated to include PKCE parameters
    public func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?,
        codeChallenge: String?,
        codeChallengeMethod: String?
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
