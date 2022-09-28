import Vapor

struct LocalOAuthHelper: OAuthHelperProtocol {

    weak var request: Request?
    let tokenAuthenticator: TokenAuthenticator?
    let userManager: UserManager?
    let tokenManager: TokenManager?

    func assertScopes(_ scopes: [String]?) throws {
        guard let tokenAuthenticator = tokenAuthenticator else {
            throw Abort(.forbidden)
        }

        let accessToken = try getToken()

        guard tokenAuthenticator.validateAccessToken(accessToken, requiredScopes: scopes) else {
            throw Abort(.unauthorized)
        }
    }

    func user() throws -> OAuthUser {
        guard let userManager = userManager else {
            throw Abort(.forbidden)
        }

        let token = try getToken()

        guard let userID = token.userID else {
            throw Abort(.unauthorized)
        }

        guard let user = userManager.getUser(userID: userID) else {
            throw Abort(.unauthorized)
        }

        return user
    }

    private func getToken() throws -> AccessToken {
        guard let tokenManager = tokenManager, let token = try request?.getOAuthToken() else {
            throw Abort(.forbidden)
        }

        guard let accessToken = tokenManager.getAccessToken(token) else {
            throw Abort(.unauthorized)
        }

        guard accessToken.expiryTime >= Date() else {
            throw Abort(.unauthorized)
        }

        return accessToken
    }
}
