import Vapor

struct RefreshTokenHandler {

    let scopeValidator: ScopeValidator
    let tokenManager: TokenManager
    let clientValidator: ClientValidator
    let tokenAuthenticator: TokenAuthenticator
    let tokenResponseGenerator: TokenResponseGenerator

    func handleRefreshTokenRequest(_ request: Request) async throws -> Response {

        let (errorResponseReturned, refreshTokenRequestReturned) = try await validateRefreshTokenRequest(request)

        if let errorResponse = errorResponseReturned {
            return errorResponse
        }

        guard let refreshTokenRequest = refreshTokenRequestReturned else {
            throw Abort(.internalServerError)
        }

        let scopesString: String? = request.content[OAuthRequestParameters.scope]
        var scopesRequested = scopesString?.components(separatedBy: " ")

        if let scopes = scopesRequested {

            do {
                try await scopeValidator.validateScope(clientID: refreshTokenRequest.clientID, scopes: scopes)
            } catch ScopeError.invalid {
                return try tokenResponseGenerator.createResponse(
                    error: OAuthResponseParameters.ErrorType.invalidScope,
                    description: "Request contained an invalid scope"
                )
            } catch ScopeError.unknown {
                return try tokenResponseGenerator.createResponse(
                    error: OAuthResponseParameters.ErrorType.invalidScope,
                    description: "Request contained an unknown scope"
                )
            }

            if let tokenScopes = refreshTokenRequest.refreshToken.scopes {
                for scope in scopes where !tokenScopes.contains(scope) {
                    return try tokenResponseGenerator.createResponse(
                        error: OAuthResponseParameters.ErrorType.invalidScope,
                        description: "Request contained elevated scopes"
                    )
                }
            } else {
                return try tokenResponseGenerator.createResponse(
                    error: OAuthResponseParameters.ErrorType.invalidScope,
                    description: "Request contained elevated scopes"
                )
            }

            try await tokenManager.updateRefreshToken(refreshTokenRequest.refreshToken, scopes: scopes)
        } else {
            scopesRequested = refreshTokenRequest.refreshToken.scopes
        }

        let expiryTime = 3600
        let accessToken = try await tokenManager.generateAccessToken(
            clientID: refreshTokenRequest.clientID,
            userID: refreshTokenRequest.refreshToken.userID,
            scopes: scopesRequested,
            expiryTime: expiryTime
        )

        return try tokenResponseGenerator.createResponse(
            accessToken: accessToken,
            refreshToken: nil,
            expires: expiryTime,
            scope: scopesString
        )
    }

    private func validateRefreshTokenRequest(_ request: Request) async throws -> (Response?, RefreshTokenRequest?) {
        guard let clientID: String = request.content[OAuthRequestParameters.clientID] else {
            let errorResponse = try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'client_id' parameter"
            )
            return (errorResponse, nil)
        }

        guard let clientSecret: String = request.content[OAuthRequestParameters.clientSecret] else {
            let errorResponse = try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'client_secret' parameter"
            )
            return (errorResponse, nil)
        }

        do {
            try await clientValidator.authenticateClient(
                clientID: clientID,
                clientSecret: clientSecret,
                grantType: nil,
                checkConfidentialClient: true
            )
        } catch ClientError.unauthorized {
            let errorResponse = try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidClient,
                description: "Request had invalid client credentials",
                status: .unauthorized
            )
            return (errorResponse, nil)
        } catch ClientError.notConfidential {
            let errorDescription = "You are not authorized to use the Client Credentials grant type"
            let errorResponse = try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.unauthorizedClient,
                description: errorDescription
            )
            return (errorResponse, nil)
        }

        guard let refreshTokenString: String = request.content[OAuthRequestParameters.refreshToken] else {
            let errorResponse = try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidRequest,
                description: "Request was missing the 'refresh_token' parameter"
            )
            return (errorResponse, nil)
        }

        guard let refreshToken = try await tokenManager.getRefreshToken(refreshTokenString),
            tokenAuthenticator.validateRefreshToken(refreshToken, clientID: clientID)
        else {
            let errorResponse = try tokenResponseGenerator.createResponse(
                error: OAuthResponseParameters.ErrorType.invalidGrant,
                description: "The refresh token is invalid"
            )
            return (errorResponse, nil)
        }

        let refreshTokenRequest = RefreshTokenRequest(clientID: clientID, clientSecret: clientSecret, refreshToken: refreshToken)
        return (nil, refreshTokenRequest)
    }
}

struct RefreshTokenRequest {
    let clientID: String
    let clientSecret: String
    let refreshToken: RefreshToken
}
