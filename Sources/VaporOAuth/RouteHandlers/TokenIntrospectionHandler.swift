import Vapor

struct TokenIntrospectionHandler {
    let clientValidator: ClientValidator
    let tokenManager: TokenManager
    let userManager: UserManager

    func handleRequest(_ req: Request) async throws -> Response {

        struct TokenData: Content {
            let token: String
        }

        let tokenString: String
        do {
            tokenString = try req.content.decode(TokenData.self).token
        } catch {
            return try createErrorResponse(
                status: .badRequest,
                errorMessage: OAuthResponseParameters.ErrorType.missingToken,
                errorDescription: "The token parameter is required"
            )
        }

        guard let token = try await tokenManager.getAccessToken(tokenString) else {
            return try createTokenResponse(active: false, expiryDate: nil, clientID: nil)
        }

        guard token.expiryTime >= Date() else {
            return try createTokenResponse(active: false, expiryDate: nil, clientID: nil)
        }

        let scopes = token.scopes?.joined(separator: " ")
        var user: OAuthUser? = nil

        if let userID = token.userID {
            if let tokenUser = try await userManager.getUser(userID: userID) {
                user = tokenUser
            }
        }

        return try createTokenResponse(
            active: true,
            expiryDate: token.expiryTime,
            clientID: token.clientID,
            scopes: scopes,
            user: user
        )
    }

    func createTokenResponse(
        active: Bool,
        expiryDate: Date?,
        clientID: String?,
        scopes: String? = nil,
        user: OAuthUser? = nil
    ) throws -> Response {
        var tokenResponse = TokenResponse(
            active: active,
            scope: scopes,
            clientID: clientID,
            username: user?.username
        )

        if let expiryDate = expiryDate {
            tokenResponse.exp = Int(expiryDate.timeIntervalSince1970)
        }

        let response = Response(status: .ok)
        try response.content.encode(tokenResponse)
        return response
    }

    func createErrorResponse(status: HTTPStatus, errorMessage: String, errorDescription: String) throws -> Response {
        let response = Response(status: status)
        try response.content.encode(ErrorResponse(error: errorMessage, errorDescription: errorDescription))
        return response
    }
}

extension TokenIntrospectionHandler {
    struct ErrorResponse: Content {
        var error: String
        var errorDescription: String

        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }

    struct TokenResponse: Content {
        let active: Bool
        var scope: String?
        var clientID: String?
        var username: String?
        var exp: Int?

        enum CodingKeys: String, CodingKey {
            case active
            case scope
            case clientID = "client_id"
            case username
            case exp
        }
    }
}
