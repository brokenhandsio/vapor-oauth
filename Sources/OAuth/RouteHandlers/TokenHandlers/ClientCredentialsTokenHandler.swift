import Vapor

struct ClientCredentialsTokenHandler {

    let clientValidator: ClientValidator
    let scopeValidator: ScopeValidator
    let tokenManager: TokenManager
    let tokenResponseGenerator: TokenResponseGenerator

    func handleClientCredentialsTokenRequest(_ request: Request) throws -> Response {
        guard let clientID = request.data[OAuthRequestParameters.clientID]?.string else {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                                             description: "Request was missing the 'client_id' parameter")
        }

        guard let clientSecret = request.data[OAuthRequestParameters.clientSecret]?.string else {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                                             description: "Request was missing the 'client_secret' parameter")
        }

        do {
            try clientValidator.authenticateClient(clientID: clientID, clientSecret: clientSecret,
                                                   grantType: .clientCredentials, checkConfidentialClient: true)
        } catch ClientError.unauthorized {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                                             description: "Request had invalid client credentials", status: .unauthorized)
        } catch ClientError.notConfidential {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                                             description: "You are not authorized to use the Client Credentials grant type")
        }

        let scopeString = request.data[OAuthRequestParameters.scope]?.string
        if let scopes = scopeString {
            do {
                try scopeValidator.validateScope(clientID: clientID, scopes: scopes.components(separatedBy: " "))
            } catch ScopeError.invalid {
                return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                                                 description: "Request contained an invalid scope")
            } catch ScopeError.unknown {
                return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                                                 description: "Request contained an unknown scope")
            }
        }

        let expiryTime = 3600
        let scopes = scopeString?.components(separatedBy: " ")
        let (access, refresh) = try tokenManager.generateAccessRefreshTokens(clientID: clientID, userID: nil,
                                                                             scopes: scopes,
                                                                             accessTokenExpiryTime: expiryTime)

        return try tokenResponseGenerator.createResponse(accessToken: access, refreshToken: refresh, expires: expiryTime, scope: scopeString)
    }
}
