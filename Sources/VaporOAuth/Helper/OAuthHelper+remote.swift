import Vapor

extension OAuthHelper {
    public static func remote(
        tokenIntrospectionEndpoint: String,
        client: Client,
        resourceServerUsername: String,
        resourceServerPassword: String
    ) -> Self {
        var remoteTokenResponse: RemoteTokenResponse?
        return OAuthHelper(
            assertScopes: { scopes, request in
                if remoteTokenResponse == nil {
                    try await setupRemoteTokenResponse(
                        request: request,
                        tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                        client: client,
                        resourceServerUsername: resourceServerUsername,
                        resourceServerPassword: resourceServerPassword,
                        remoteTokenResponse: &remoteTokenResponse
                    )
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
            },
            user: { request in
                if remoteTokenResponse == nil {
                    try await setupRemoteTokenResponse(
                        request: request,
                        tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                        client: client,
                        resourceServerUsername: resourceServerUsername,
                        resourceServerPassword: resourceServerPassword,
                        remoteTokenResponse: &remoteTokenResponse
                    )
                }

                guard let remoteTokenResponse = remoteTokenResponse else {
                    throw Abort(.internalServerError)
                }

                guard let user = remoteTokenResponse.user else {
                    throw Abort(.unauthorized)
                }

                return user
            }
        )
    }

    private static func setupRemoteTokenResponse(
        request: Request,
        tokenIntrospectionEndpoint: String,
        client: Client,
        resourceServerUsername: String,
        resourceServerPassword: String,
        remoteTokenResponse: inout RemoteTokenResponse?
    ) async throws {
        let token = try request.getOAuthToken()

        var headers = HTTPHeaders()
        headers.basicAuthorization = .init(
            username: resourceServerUsername,
            password: resourceServerPassword
        )

        struct Token: Content {
            let token: String
        }
        let tokenInfoResponse = try await client.post(
            URI(string: tokenIntrospectionEndpoint),
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

        remoteTokenResponse = RemoteTokenResponse(scopes: scopes, user: oauthUser)

    }
}

struct RemoteTokenResponse {
    let scopes: [String]?
    let user: OAuthUser?
}
