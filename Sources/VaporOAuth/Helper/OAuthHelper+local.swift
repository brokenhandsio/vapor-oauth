import Vapor

extension OAuthHelper {
    public static func local(
        tokenAuthenticator: TokenAuthenticator?,
        userManager: UserManager?,
        tokenManager: TokenManager?
    ) -> Self {
        OAuthHelper(
            assertScopes: { scopes, request in
                guard let tokenAuthenticator = tokenAuthenticator else {
                    throw Abort(.forbidden)
                }

                let accessToken = try await getToken(tokenManager: tokenManager, request: request)

                guard tokenAuthenticator.validateAccessToken(accessToken, requiredScopes: scopes) else {
                    throw Abort(.unauthorized)
                }
            },
            user: { request in
                guard let userManager = userManager else {
                    throw Abort(.forbidden)
                }

                let token = try await getToken(tokenManager: tokenManager, request: request)

                guard let userID = token.userID else {
                    throw Abort(.unauthorized)
                }

                guard let user = try await userManager.getUser(userID: userID) else {
                    throw Abort(.unauthorized)
                }

                return user
            }
        )
    }

    private static func getToken(tokenManager: TokenManager?, request: Request) async throws -> AccessToken {
        guard let tokenManager = tokenManager else {
            throw Abort(.forbidden)
        }

        let token = try request.getOAuthToken()

        guard let accessToken = try await tokenManager.getAccessToken(token) else {
            throw Abort(.unauthorized)
        }

        guard accessToken.expiryTime >= Date() else {
            throw Abort(.unauthorized)
        }

        return accessToken
    }
}
