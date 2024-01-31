import VaporOAuth
import Foundation

class StubTokenManager: TokenManager {
    
    func generateTokens(clientID: String, userID: String?, scopes: [String]?, accessTokenExpiryTime: Int, idTokenExpiryTime: Int, nonce: String?) async throws -> (VaporOAuth.AccessToken, VaporOAuth.RefreshToken, VaporOAuth.IDToken) {
        // Generate access and refresh tokens
        let (accessToken, refreshToken) = try generateAccessRefreshTokens(clientID: clientID, userID: userID, scopes: scopes, accessTokenExpiryTime: accessTokenExpiryTime)
        
        // Generate ID token
        let idToken = try await generateIDToken(clientID: clientID, userID: userID ?? "", scopes: scopes, expiryTime: idTokenExpiryTime, nonce: nonce)
        
        return (accessToken, refreshToken, idToken)
    }
    
    func generateIDToken(clientID: String, userID: String, scopes: [String]?, expiryTime: Int, nonce: String?) async throws -> VaporOAuth.IDToken {
        // Create an instance of your custom IDToken struct and set its properties
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
