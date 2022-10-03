import Vapor

class RemoteOAuthHelper: OAuthHelperProtocol {
    weak var request: Request?
    let tokenIntrospectionEndpoint: String
    let client: Client
    let resourceServerUsername: String
    let resourceServerPassword: String
    var remoteTokenResponse: RemoteTokenResponse?

    init(request: Request, tokenIntrospectionEndpoint: String, client: Client,
         resourceServerUsername: String, resourceServerPassword: String) {
        self.request = request
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.client = client
        self.resourceServerUsername = resourceServerUsername
        self.resourceServerPassword = resourceServerPassword
        self.remoteTokenResponse = nil
    }

    func assertScopes(_ scopes: [String]?) async throws {
        if remoteTokenResponse == nil {
            try await setupRemoteTokenResponse()
        }

        guard let remoteTokenResponse = remoteTokenResponse else {
            throw Abort(.internalServerError)
        }

        if let requiredScopes = scopes {
            guard let tokenScopes = remoteTokenResponse.scopes else {
                throw Abort(.unauthorized)
            }

            for scope in requiredScopes {
                if !tokenScopes.contains(scope) {
                    throw Abort(.unauthorized)
                }
            }
        }

    }

    func user() async throws -> OAuthUser {
        if remoteTokenResponse == nil {
            try await setupRemoteTokenResponse()
        }

        guard let remoteTokenResponse = remoteTokenResponse else {
            throw Abort(.internalServerError)
        }

        guard let user = remoteTokenResponse.user else {
            throw Abort(.unauthorized)
        }

        return user
    }

    private func setupRemoteTokenResponse() async throws {
        guard let token = try request?.getOAuthToken() else {
            throw Abort(.forbidden)
        }

        var headers = HTTPHeaders()
        headers.basicAuthorization = .init(
            username: resourceServerUsername,
            password: resourceServerPassword
        )

        struct Token: Content {
            let token: String
        }
        let tokenInfoResponse = try await client.post(
            URI(stringLiteral: tokenIntrospectionEndpoint),
            headers: headers,
            content: Token(token: token)
        ).get()

        let tokenInfoJSON = tokenInfoResponse.content

        guard let tokenActive: Bool = tokenInfoJSON[OAuthResponseParameters.active], tokenActive else {
            throw Abort(.unauthorized)
        }

        var scopes: [String]?
        var oauthUser: OAuthUser?

        if let tokenScopes: String = tokenInfoJSON[OAuthResponseParameters.scope] {
            scopes = tokenScopes.components(separatedBy: " ")
        }

        if let userID: String = tokenInfoJSON[OAuthResponseParameters.userID] {
            guard let username: String = tokenInfoJSON[OAuthResponseParameters.username] else {
                throw Abort(.internalServerError)
            }
            oauthUser = OAuthUser(userID: userID, username: username,
                                  emailAddress: tokenInfoJSON[String.self, at: OAuthResponseParameters.email],
                                  password: "")
        }

        self.remoteTokenResponse = RemoteTokenResponse(scopes: scopes, user: oauthUser)

    }
}

struct RemoteTokenResponse {
    let scopes: [String]?
    let user: OAuthUser?
}
