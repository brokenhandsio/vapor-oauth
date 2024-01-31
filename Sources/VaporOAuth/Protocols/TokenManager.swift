/// A protocol that defines the behavior of a token manager.
public protocol TokenManager: Sendable {
    
    /// Generates access, refresh, and ID tokens. Should be called after successful authentication.
    /// - Parameters:
    ///   - clientID: The client ID.
    ///   - userID: The user ID.
    ///   - scopes: The scopes.
    ///   - accessTokenExpiryTime: The expiry time for the access token.
    ///   - idTokenExpiryTime: The expiry time for the ID token.
    ///   - nonce: The nonce.
    /// - Returns: A tuple containing the generated access token, refresh token, and ID token.
    func generateTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int,
        idTokenExpiryTime: Int,
        nonce: String?
    ) async throws -> (AccessToken, RefreshToken, IDToken)
    
    /// Generates only an access token. Should be called after successful authentication.
    /// - Parameters:
    ///   - clientID: The client ID.
    ///   - userID: The user ID.
    ///   - scopes: The scopes.
    ///   - expiryTime: The expiry time for the access token.
    /// - Returns: The generated access token.
    func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) async throws -> AccessToken
    
    /// Generates both access and refresh tokens. Should be called after successful PKCE validation.
    /// - Parameters:
    ///   - clientID: The client ID.
    ///   - userID: The user ID.
    ///   - scopes: The scopes.
    ///   - accessTokenExpiryTime: The expiry time for the access token.
    /// - Returns: A tuple containing the generated access token and refresh token.
    func generateAccessRefreshTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int
    ) async throws -> (AccessToken, RefreshToken)
    
    /// Retrieves a refresh token by its string representation.
    /// - Parameter refreshToken: The string representation of the refresh token.
    /// - Returns: The refresh token, if found. Otherwise, `nil`.
    func getRefreshToken(_ refreshToken: String) async throws -> RefreshToken?
    
    /// Retrieves an access token by its string representation.
    /// - Parameter accessToken: The string representation of the access token.
    /// - Returns: The access token, if found. Otherwise, `nil`.
    func getAccessToken(_ accessToken: String) async throws -> AccessToken?
    
    /// Updates a refresh token, typically to change its scope.
    /// - Parameters:
    ///   - refreshToken: The refresh token to update.
    ///   - scopes: The new scopes for the refresh token.
    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String]) async throws
    
    /// Generates an ID token. Should be called after successful authentication.
    /// - Parameters:
    ///   - clientID: The client ID.
    ///   - userID: The user ID.
    ///   - scopes: The scopes.
    ///   - expiryTime: The expiry time for the ID token.
    ///   - nonce: The nonce.
    /// - Returns: The generated ID token.
    func generateIDToken(
        clientID: String,
        userID: String,
        scopes: [String]?,
        expiryTime: Int,
        nonce: String?
    ) async throws -> IDToken
}
