/// Responsible for generating and managing OAuth Codes
public protocol CodeManager: Sendable {
    // Updated to include PKCE parameters
    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?, codeChallenge: String?, codeChallengeMethod: String?) async throws -> String
    func getCode(_ code: String) async throws -> OAuthCode?

    // This is explicit to ensure that the code is marked as used or deleted (it could be implied that this is done when you call
    // `getCode` but it is called explicitly to remind developers to ensure that codes can't be reused)
    func codeUsed(_ code: OAuthCode) async throws
    func generateDeviceCode(userID: String, clientID: String, scopes: [String]?) async throws -> String
    func getDeviceCode(_ deviceCode: String) async throws -> OAuthDeviceCode?
    func deviceCodeUsed(_ deviceCode: OAuthDeviceCode) async throws
}
