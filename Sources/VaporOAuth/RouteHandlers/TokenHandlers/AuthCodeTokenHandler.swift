import Vapor

struct AuthCodeTokenHandler {

    let clientValidator: ClientValidator
    let tokenManager: TokenManager
    let codeManager: CodeManager
    let codeValidator = CodeValidator()
    let tokenResponseGenerator: TokenResponseGenerator

    func handleAuthCodeTokenRequest(_ request: Request) async throws -> Response {
        guard let codeString: String = request.content[OAuthRequestParameters.code] else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'code' parameter"
            )
        }

        guard let redirectURI: String = request.content[OAuthRequestParameters.redirectURI] else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'redirect_uri' parameter"
            )
        }

        guard let clientID: String = request.content[OAuthRequestParameters.clientID] else {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'client_id' parameter"
            )
        }

        do {
            try await clientValidator.authenticateClient(
                clientID: clientID,
                clientSecret: request.content[String.self, at: OAuthRequestParameters.clientSecret],
                grantType: .authorization
            )
        } catch {
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidClient,
                description: "Request had invalid client credentials",
                status: .unauthorized
            )
        }

        guard let code = try await codeManager.getCode(codeString),
            codeValidator.validateCode(code, clientID: clientID, redirectURI: redirectURI)
        else {
            let errorDescription = "The code provided was invalid or expired, or the redirect URI did not match"
            return try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidGrant,
                description: errorDescription
            )
        }

        try await codeManager.codeUsed(code)

        let scopes = code.scopes
        let expiryTime = 3600

        let (access, refresh) = try await tokenManager.generateAccessRefreshTokens(
            clientID: clientID,
            userID: code.userID,
            scopes: scopes,
            accessTokenExpiryTime: expiryTime
        )

        return try tokenResponseGenerator.createResponse(
            accessToken: access,
            refreshToken: refresh,
            expires: Int(expiryTime),
            scope: scopes?.joined(separator: " ")
        )
    }
}
