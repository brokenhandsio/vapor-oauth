import Vapor

public protocol TokenManager {
    func generateAccessRefreshTokens(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        accessTokenExpiryTime: Int
    ) throws -> (AccessToken, RefreshToken)

    func generateAccessToken(
        clientID: String,
        userID: String?,
        scopes: [String]?,
        expiryTime: Int
    ) throws -> AccessToken
    
    func getRefreshToken(_ refreshToken: String) -> RefreshToken?
    func getAccessToken(_ accessToken: String) -> AccessToken?
    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String])
}
