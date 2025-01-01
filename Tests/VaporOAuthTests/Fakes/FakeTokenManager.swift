import Foundation
import VaporOAuth

class FakeTokenManager: TokenManager {

    var accessTokenToReturn = "ACCESS-TOKEN-STRING"
    var refreshTokenToReturn = "REFRESH-TOKEN-STRING"
    var refreshTokens: [String: RefreshToken] = [:]
    var accessTokens: [String: AccessToken] = [:]
    var currentTime = Date()

    func getRefreshToken(_ refreshToken: String) -> RefreshToken? {
        return refreshTokens[refreshToken]
    }

    func getAccessToken(_ accessToken: String) -> AccessToken? {
        return accessTokens[accessToken]
    }

    func generateAccessRefreshTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int) throws -> (
        AccessToken, RefreshToken
    ) {
        let accessToken = FakeAccessToken(
            tokenString: accessTokenToReturn, clientID: clientID, userID: userID, scopes: scopes,
            expiryTime: currentTime.addingTimeInterval(TimeInterval(accessTokenExpiryTime)))
        let refreshToken = FakeRefreshToken(tokenString: refreshTokenToReturn, clientID: clientID, userID: userID, scopes: scopes)

        accessTokens[accessTokenToReturn] = accessToken
        refreshTokens[refreshTokenToReturn] = refreshToken
        return (accessToken, refreshToken)
    }

    func generateAccessToken(clientID: String, userID: String?, scopes: [String]?, expiryTime: Int) throws -> AccessToken {
        let accessToken = FakeAccessToken(
            tokenString: accessTokenToReturn, clientID: clientID, userID: userID, scopes: scopes,
            expiryTime: currentTime.addingTimeInterval(TimeInterval(expiryTime)))
        accessTokens[accessTokenToReturn] = accessToken
        return accessToken
    }

    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String]) {
        var tempRefreshToken = refreshToken
        tempRefreshToken.scopes = scopes
        refreshTokens[refreshToken.tokenString] = tempRefreshToken
    }
}
