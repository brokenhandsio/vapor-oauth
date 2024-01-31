import VaporOAuth
import Foundation

class StubTokenManager: TokenManager {
    
    var accessToken = "ABCDEF"
    var refreshToken = "GHIJKL"
    var deviceCodes: [String: OAuthDeviceCode] = [:]

    func generateAccessRefreshTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int) throws -> (AccessToken, RefreshToken) {
        let access = FakeAccessToken(tokenString: accessToken, clientID: clientID, userID: userID, scopes: scopes, expiryTime: Date())
        let refresh = FakeRefreshToken(tokenString: refreshToken, clientID: clientID, userID: nil, scopes: scopes)
        return (access, refresh)
    }
    
    func generateAccessToken(clientID: String, userID: String?, scopes: [String]?, expiryTime: Int) throws -> AccessToken {
        return FakeAccessToken(tokenString: accessToken, clientID: clientID, userID: userID, scopes: scopes, expiryTime: Date())
    }
    
    func getRefreshToken(_ refreshToken: String) -> RefreshToken? {
        return nil
    }
    
    func getAccessToken(_ accessToken: String) -> AccessToken? {
        return nil
    }
    
    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String]) {
    }
}
