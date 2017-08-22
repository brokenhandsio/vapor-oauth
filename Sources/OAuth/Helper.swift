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

    let isLocal: Bool
    weak var request: Request?
    let tokenAuthenticator: TokenAuthenticator?
    let tokenManager: TokenManager?
    let userManager: UserManager?
    let tokenIntrospectionEndpoint: String?
    let client: ClientFactoryProtocol?
    let resourceServerUsername: String?
    let resourceServerPassword: String?

    var remoteTokenResponse: RemoteTokenResponse?

    init(request: Request, provider: OAuth2Provider?) {
        self.isLocal = true
        self.request = request
        self.tokenAuthenticator = provider?.tokenHandler.tokenAuthenticator
        self.tokenManager = provider?.tokenManager
        self.userManager = provider?.userManager
        self.tokenIntrospectionEndpoint = nil
        self.client = nil
        self.resourceServerUsername = nil
        self.resourceServerPassword = nil
    }

    init(request: Request, tokenIntrospectionEndpoint: String, client: ClientFactoryProtocol,
         resourceServerUsername: String, resourceServerPassword: String) {
        self.request = request
        self.isLocal = false
        self.tokenManager = nil
        self.tokenAuthenticator = nil
        self.userManager = nil
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.client = client
        self.resourceServerUsername = resourceServerUsername
        self.resourceServerPassword = resourceServerPassword
    }

    public func assertScopes(_ scopes: [String]?) throws {
        if isLocal {
            try assertLocalScopes(scopes)
        } else {
            try assertRemoteScopes(scopes)
        }
    }

    private func assertLocalScopes(_ scopes: [String]?) throws {
        guard let tokenAuthenticator = tokenAuthenticator else {
            throw Abort(.forbidden)
        }

        let accessToken = try getToken()

        guard tokenAuthenticator.validateAccessToken(accessToken, requiredScopes: scopes) else {
            throw Abort.unauthorized
        }
    }

    private func assertRemoteScopes(_ scopes: [String]?) throws {
        if remoteTokenResponse == nil {
            try setupRemoteTokenResponse()
        }

        guard let remoteTokenResponse = remoteTokenResponse else {
            throw Abort.serverError
        }

        if let requiredScopes = scopes {
            guard let tokenScopes = remoteTokenResponse.scopes else {
                throw Abort.unauthorized
            }

            for scope in requiredScopes {
                if !tokenScopes.contains(scope) {
                    throw Abort.unauthorized
                }
            }
        }
    }

    public func user() throws -> OAuthUser {
        if isLocal {
            return try getLocalUser()
        } else {
            return try getRemoteUser()
        }
    }

    private func getLocalUser() throws -> OAuthUser {
        guard let userManager = userManager else {
            throw Abort(.forbidden)
        }

        let token = try getToken()

        guard let userID = token.userID else {
            throw Abort.unauthorized
        }

        guard let user = userManager.getUser(userID: userID) else {
            throw Abort.unauthorized
        }

        return user
    }

    private func getRemoteUser() throws -> OAuthUser {
        if remoteTokenResponse == nil {
            try setupRemoteTokenResponse()
        }

        guard let remoteTokenResponse = remoteTokenResponse else {
            throw Abort.serverError
        }

        guard let user = remoteTokenResponse.user else {
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

    private func setupRemoteTokenResponse() throws {
        guard let request = request, let tokenIntrospectionEndpoint = tokenIntrospectionEndpoint,
            let client = client, let resourceServerUsername = resourceServerUsername,
            let resourceServerPassword = resourceServerPassword else {
            throw Abort.serverError
        }

        guard let authHeader = request.headers[.authorization] else {
            throw Abort(.forbidden)
        }

        guard authHeader.lowercased().hasPrefix("bearer ") else {
            throw Abort(.forbidden)
        }

        let token = authHeader.substring(from: authHeader.index(authHeader.startIndex, offsetBy: 7))

        guard !token.isEmpty else {
            throw Abort(.forbidden)
        }

        let tokenRequest = Request(method: .post, uri: tokenIntrospectionEndpoint)
        var tokenRequestJSON = JSON()
        try tokenRequestJSON.set("token", token)
        tokenRequest.json = tokenRequestJSON

        let resourceAuthHeader = "\(resourceServerUsername):\(resourceServerPassword)".makeBytes().base64Encoded.makeString()
        tokenRequest.headers[.authorization] = "Basic \(resourceAuthHeader)"

        let tokenInfoResponse = try client.respond(to: tokenRequest)

        guard let tokenInfoJSON = tokenInfoResponse.json else {
            throw Abort.serverError
        }

        guard let tokenActive = tokenInfoJSON[OAuthResponseParameters.active]?.bool, tokenActive else {
            throw Abort.unauthorized
        }

        var scopes: [String]?
        var oauthUser: OAuthUser?

        if let tokenScopes = tokenInfoJSON[OAuthResponseParameters.scope]?.string {
            scopes = tokenScopes.components(separatedBy: " ")
        }

        if let userID = tokenInfoJSON[OAuthResponseParameters.userID]?.string {
            guard let username = tokenInfoJSON[OAuthResponseParameters.username]?.string else {
                throw Abort.serverError
            }
            let userIdentifier: Identifier = Identifier(userID, in: nil)
            oauthUser = OAuthUser(userID: userIdentifier, username: username,
                                  emailAddress: tokenInfoJSON[OAuthResponseParameters.email]?.string,
                                  password: "".makeBytes())
        }

        self.remoteTokenResponse = RemoteTokenResponse(scopes: scopes, user: oauthUser)

    }
}

struct RemoteTokenResponse {
    let scopes: [String]?
    let user: OAuthUser?
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
