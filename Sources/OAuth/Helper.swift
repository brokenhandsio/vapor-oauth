import HTTP
import Vapor

let oauthHelperKey = "oauth-helper"

public final class Helper {
    weak var request: Request?
    let tokenAuthenticator: TokenAuthenticator?
    let tokenManager: TokenManager?
    let userManager: UserManager?
    init(request: Request, provider: OAuth2Provider?) {
        self.request = request
        self.tokenAuthenticator = provider?.tokenAuthenticator
        self.tokenManager = provider?.tokenManager
        self.userManager = provider?.userManager
    }
    
    public func assertScopes(_ scopes: [String]?) throws {
        guard let tokenAuthenticator = tokenAuthenticator else {
            throw Abort(.forbidden)
        }
        
        let accessToken = try getToken()
        
        guard tokenAuthenticator.validateAccessToken(accessToken, requiredScopes: scopes) else {
            throw Abort.unauthorized
        }
    }
    
    public func user() throws -> OAuthUser {
        guard let userManager = userManager else {
            throw Abort(.forbidden)
        }
        
        let token = try getToken()
        
        guard let userID = token.userID else {
            throw Abort.unauthorized
        }
        
        guard let user = userManager.getUser(id: userID) else {
            throw Abort.unauthorized
        }
        
        return user
    }
    
    private func getToken() throws -> AccessToken {
        guard let tokenManager = tokenManager else {
            throw Abort(.forbidden)
        }
        
        guard let authHeader = request?.headers[.authorization] else {
            throw Abort(.forbidden)
        }
        
        guard authHeader.lowercased().hasPrefix("bearer ") else {
            throw Abort(.forbidden)
        }
        
        let token = authHeader.substring(from: authHeader.index(authHeader.startIndex, offsetBy: 7))
        
        guard !token.isEmpty else {
            throw Abort(.forbidden)
        }
        
        guard let accessToken = tokenManager.getAccessToken(token) else {
            throw Abort.unauthorized
        }
        
        guard accessToken.expiryTime >= Date() else {
            throw Abort.unauthorized
        }
        
        return accessToken
    }
}


extension Request {
    public var oauth: Helper {
        if let existing = storage[oauthHelperKey] as? Helper {
            return existing
        }
        
        let helper = Helper(request: self, provider: Request.oauthProvider)
        storage[oauthHelperKey] = helper
        
        return helper
    }
    
    static var oauthProvider: OAuth2Provider?
}
