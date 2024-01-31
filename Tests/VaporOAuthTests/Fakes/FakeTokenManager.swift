import VaporOAuth
import Foundation

// Define your custom IDToken conforming struct
struct MyIDToken: VaporOAuth.IDToken {
    var tokenString: String = ""
    var issuer: String = ""
    var subject: String = ""
    var audience: [String] = []
    var expiration: Date = Date()
    var issuedAt: Date = Date()
    var nonce: String? = nil
    var authTime: Date? = nil
    // Additional claims can be added as needed
}

class FakeTokenManager: TokenManager {
    
    func generateTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int, idTokenExpiryTime: Int, nonce: String?) async throws -> (VaporOAuth.AccessToken, VaporOAuth.RefreshToken, VaporOAuth.IDToken) {
        // Generate access token
        let accessToken = try generateAccessToken(clientID: clientID, userID: userID, scopes: scopes, expiryTime: accessTokenExpiryTime)
        
        // Generate refresh token
        let refreshToken = try generateAccessRefreshTokens(clientID: clientID, userID: userID, scopes: scopes, accessTokenExpiryTime: accessTokenExpiryTime).1
        
        // Generate ID token
        let idToken = try await generateIDToken(clientID: clientID, userID: userID ?? "", scopes: scopes, expiryTime: idTokenExpiryTime, nonce: nonce)
        
        return (accessToken, refreshToken, idToken)
    }
    
    func generateIDToken(clientID: String, userID: String, scopes: [String]?, expiryTime: Int, nonce: String?) async throws -> VaporOAuth.IDToken {
        // Create an instance of your IDToken conforming object and set its properties
        var idToken = MyIDToken()
        idToken.tokenString = "YOUR-ID-TOKEN-STRING"
        idToken.issuer = "YOUR-ISSUER"
        idToken.subject = userID
        idToken.audience = [clientID]
        idToken.expiration = Date().addingTimeInterval(TimeInterval(expiryTime))
        idToken.issuedAt = Date()
        idToken.nonce = nonce
        
        return idToken
    }
    
    
    var accessTokenToReturn = "ACCESS-TOKEN-STRING"
    var refreshTokenToReturn = "REFRESH-TOKEN-STRING"
    var refreshTokens: [String: RefreshToken] = [:]
    var accessTokens: [String: AccessToken] = [:]
    var deviceCodes: [String: OAuthDeviceCode] = [:]
    var currentTime = Date()
    
    func getRefreshToken(_ refreshToken: String) -> RefreshToken? {
        return refreshTokens[refreshToken]
    }
    
    func getAccessToken(_ accessToken: String) -> AccessToken? {
        return accessTokens[accessToken]
    }
    
    func generateAccessRefreshTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int) throws -> (AccessToken, RefreshToken) {
        let accessToken = FakeAccessToken(tokenString: accessTokenToReturn, clientID: clientID, userID: userID, scopes: scopes, expiryTime: currentTime.addingTimeInterval(TimeInterval(accessTokenExpiryTime)))
        let refreshToken = FakeRefreshToken(tokenString: refreshTokenToReturn, clientID: clientID, userID: userID, scopes: scopes)
        
        accessTokens[accessTokenToReturn] = accessToken
        refreshTokens[refreshTokenToReturn] = refreshToken
        return (accessToken, refreshToken)
    }
    
    func generateAccessToken(clientID: String, userID: String?, scopes: [String]?, expiryTime: Int) throws -> AccessToken {
        let accessToken = FakeAccessToken(tokenString: accessTokenToReturn, clientID: clientID, userID: userID, scopes: scopes, expiryTime: currentTime.addingTimeInterval(TimeInterval(expiryTime)))
        accessTokens[accessTokenToReturn] = accessToken
        return accessToken
    }
    
    func updateRefreshToken(_ refreshToken: RefreshToken, scopes: [String]) {
        var tempRefreshToken = refreshToken
        tempRefreshToken.scopes = scopes
        refreshTokens[refreshToken.tokenString] = tempRefreshToken
    }
    
}
