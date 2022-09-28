import Vapor

let oauthHelperKey = "oauth-helper"

public final class OAuthHelper: OAuthHelperProtocol {
    let oauthHelper: OAuthHelperProtocol

    init(request: Request, provider: OAuth2Provider?) {
        self.oauthHelper = LocalOAuthHelper(request: request, tokenAuthenticator: provider?.tokenHandler.tokenAuthenticator,
                                            userManager: provider?.userManager, tokenManager: provider?.tokenManager)
    }

    init(request: Request, tokenIntrospectionEndpoint: String, client: Client,
         resourceServerUsername: String, resourceServerPassword: String) {
        self.oauthHelper = RemoteOAuthHelper(request: request, tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                                             client: client, resourceServerUsername: resourceServerUsername,
                                             resourceServerPassword: resourceServerPassword)
    }

    public func assertScopes(_ scopes: [String]?) async throws {
        try await oauthHelper.assertScopes(scopes)
    }

    public func user() async throws -> OAuthUser {
        return try await oauthHelper.user()
    }
}

extension Request {
//    public var oauth: Helper { application.oauth }
//        if let existing = storage[oauthHelperKey] as? Helper {
//            return existing
//        }
//
//        let helper = Helper(request: self, provider: Request.oauthProvider)
//        storage[oauthHelperKey] = helper
//
//        return helper
//    }

    static var oauthProvider: OAuth2Provider?
}

extension Request {
    func getOAuthToken() throws -> String {
        guard let token = headers.bearerAuthorization?.token else {
            throw Abort(.unauthorized)
        }

        return token
    }
}
