/// Responsible for generating and managing OAuth Codes
public protocol CodeManager: Sendable {
    /// Generates an OAuth code for the specified user, client, redirect URI, scopes, code challenge, and code challenge method.
    /// - Parameters:
    ///   - userID: The ID of the user.
    ///   - clientID: The ID of the client.
    ///   - redirectURI: The redirect URI.
    ///   - scopes: The requested scopes.
    ///   - codeChallenge: The code challenge.
    ///   - codeChallengeMethod: The code challenge method.
    /// - Returns: The generated OAuth code.
    /// - Throws: An error if the code generation fails.
    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?, codeChallenge: String?, codeChallengeMethod: String?) async throws -> String
    
    /// Retrieves the OAuth code associated with the specified code.
    /// - Parameter code: The OAuth code.
    /// - Returns: The associated OAuth code, or `nil` if not found.
    /// - Throws: An error if the retrieval fails.
    func getCode(_ code: String) async throws -> OAuthCode?
    
    /// Marks the specified OAuth code as used or deleted.
    /// - Parameter code: The OAuth code to mark as used or deleted.
    /// - Throws: An error if the operation fails.
    func codeUsed(_ code: OAuthCode) async throws
    
    /// Generates a device code for the specified user, client, and scopes.
    /// - Parameters:
    ///   - userID: The ID of the user.
    ///   - clientID: The ID of the client.
    ///   - scopes: The requested scopes.
    /// - Returns: The generated device code.
    /// - Throws: An error if the code generation fails.
    func generateDeviceCode(userID: String, clientID: String, scopes: [String]?) async throws -> String
    
    /// Retrieves the device code associated with the specified device code.
    /// - Parameter deviceCode: The device code.
    /// - Returns: The associated device code, or `nil` if not found.
    /// - Throws: An error if the retrieval fails.
    func getDeviceCode(_ deviceCode: String) async throws -> OAuthDeviceCode?
    
    /// Marks the specified device code as used or deleted.
    /// - Parameter deviceCode: The device code to mark as used or deleted.
    /// - Throws: An error if the operation fails.
    func deviceCodeUsed(_ deviceCode: OAuthDeviceCode) async throws
}
