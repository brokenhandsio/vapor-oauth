import Vapor


actor RemoteTokenResponseActor {
    var remoteTokenResponse: RemoteTokenResponse?
    
    func setRemoteTokenResponse(_ response: RemoteTokenResponse) {
        self.remoteTokenResponse = response
    }
    
    func hasTokenResponse() -> Bool {
        return remoteTokenResponse != nil
    }
    
    func getRemoteTokenResponse() throws -> RemoteTokenResponse {
        guard let response = remoteTokenResponse else {
            throw Abort(.internalServerError)
        }
        return response
    }
}

extension OAuthHelper {
    public static func remote(
        tokenIntrospectionEndpoint: String,
        client: Client,
        resourceServerUsername: String,
        resourceServerPassword: String
    ) -> Self {
        let responseActor = RemoteTokenResponseActor()
        return OAuthHelper(
            assertScopes: { scopes, request in
                if !(await responseActor.hasTokenResponse()) {
                    try await setupRemoteTokenResponse(
                        request: request,
                        tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                        client: client,
                        resourceServerUsername: resourceServerUsername,
                        resourceServerPassword: resourceServerPassword,
                        responseActor: responseActor
                    )
                }
                
                let remoteTokenResponse = try await responseActor.getRemoteTokenResponse()
                
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
                if !(await responseActor.hasTokenResponse()) {
                    try await setupRemoteTokenResponse(
                        request: request,
                        tokenIntrospectionEndpoint: tokenIntrospectionEndpoint,
                        client: client,
                        resourceServerUsername: resourceServerUsername,
                        resourceServerPassword: resourceServerPassword,
                        responseActor: responseActor
                    )
                }
                
                let remoteTokenResponse = try await responseActor.getRemoteTokenResponse()
                
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
        responseActor: RemoteTokenResponseActor
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
        
        // Update the remoteTokenResponse property of the actor
        let remoteTokenResponse = RemoteTokenResponse(scopes: scopes, user: oauthUser)
        await responseActor.setRemoteTokenResponse(remoteTokenResponse)
    }
}

struct RemoteTokenResponse {
    let scopes: [String]?
    let user: OAuthUser?
}
