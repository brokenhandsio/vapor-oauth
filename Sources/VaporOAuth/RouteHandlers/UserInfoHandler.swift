import Vapor
import JWTKit

struct UserInfoHandler {
    let tokenVerifier: JWTSigner
    let userManager: UserManager

    init(tokenVerifier: JWTSigner, userManager: UserManager) {
        self.tokenVerifier = tokenVerifier
        self.userManager = userManager
    }

    func handleRequest(_ req: Request) async throws -> OAuthUser {
        guard let bearerToken = req.headers.bearerAuthorization else {
            throw Abort(.unauthorized, reason: "No bearer token provided")
        }

        // Verify the token and extract the payload
        let accessTokenPayload = try tokenVerifier.verify(bearerToken.token, as: AccessTokenPayload.self)

        // Safely unwrap the userID
        guard let userID = accessTokenPayload.userID else {
            throw Abort(.unauthorized, reason: "Access token does not contain a user ID")
        }

        // Use the unwrapped userID to retrieve the user
        guard let user = try await userManager.getUser(userID: userID) else {
            throw Abort(.internalServerError, reason: "User not found")
        }

        return user
    }
}

struct AccessTokenPayload: AccessToken, JWTPayload {
    let tokenString: String
    let clientID: String
    let userID: String?
    let scopes: [String]?
    let expiryTime: Date

    // Implement any necessary verification logic
    func verify(using signer: JWTSigner) throws {
        // For example, verify the expiry time
        guard expiryTime > Date() else {
            throw Abort(.unauthorized, reason: "Token expired")
        }
    }
}
