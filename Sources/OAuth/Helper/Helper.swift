import HTTP
import Vapor

let oauthHelperKey = "oauth-helper"

public final class Helper {

    public static func setup(for request: Request, tokenIntrospectionEndpoint: String, client: ClientFactoryProtocol,
                             resourceServerUsername: String, resourceServerPassword: String) {
        let helper = Helper(request: request, tokenIntrospectionEndpoint: tokenIntrospectionEndpoint, client: client,
                            resourceServerUsername: resourceServerUsername, resourceServerPassword: resourceServerPassword)
        request.storage[oauthHelperKey] = helper
    }

    let oauthHelper: OAuthHelper

    init(request: Request, provider: OAuth2Provider?) {
        self.oauthHelper = LocalOAuthHelper(request: request, tokenAuthenticator: provider?.tokenHandler.tokenAuthenticator,
                                            userManager: provider?.userManager, tokenManager: provider?.tokenManager)
    }

    init(request: Request, tokenIntrospectionEndpoint: String, client: ClientFactoryProtocol,
         resourceServerUsername: String, resourceServerPassword: String) {
        self.oauthHelper = RemoteOAuthHelper(request: request, tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                                             client: client, resourceServerUsername: resourceServerUsername,
                                             resourceServerPassword: resourceServerPassword)
    }

    public func assertScopes(_ scopes: [String]?) throws {
        try oauthHelper.assertScopes(scopes)
    }

    public func user() throws -> OAuthUser {
        return try oauthHelper.user()
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
