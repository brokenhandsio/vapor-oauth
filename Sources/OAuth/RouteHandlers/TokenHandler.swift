import Vapor
import HTTP

struct TokenHandler {

    let clientValidator: ClientValidator
    let tokenManager: TokenManager
    let tokenAuthenticator = TokenAuthenticator()
    let codeValidator = CodeValidator()
    let scopeValidator: ScopeValidator
    let codeManager: CodeManager
    let userManager: UserManager
    let log: LogProtocol

    func handleRequest(request: Request) throws -> Response {
        guard let grantType = request.data[OAuthRequestParameters.grantType]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'grant_type' parameter")
        }

        switch grantType {
        case OAuthFlowType.authorization.rawValue:
            return try handleAuthCodeTokenRequest(request)
        case OAuthFlowType.password.rawValue:
            return try handlePasswordTokenRequest(request)
        case OAuthFlowType.clientCredentials.rawValue:
            return try handleClientCredentialsTokenRequest(request)
        case OAuthFlowType.refresh.rawValue:
            return try handleRefreshTokenRequest(request)
        default:
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.unsupportedGrant,
                                     description: "This server does not support the '\(grantType)' grant type")
        }

    }

    private func handleRefreshTokenRequest(_ request: Request) throws -> Response {
        guard let clientID = request.data[OAuthRequestParameters.clientID]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'client_id' parameter")
        }

        guard let clientSecret = request.data[OAuthRequestParameters.clientSecret]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'client_secret' parameter")
        }

        do {
            try clientValidator.authenticateClient(clientID: clientID, clientSecret: clientSecret,
                                                   grantType: .refresh, checkConfidentialClient: true)
        } catch ClientError.unauthorized {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                     description: "Request had invalid client credentials", status: .unauthorized)
        } catch ClientError.notConfidential {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                     description: "You are not authorized to use the Client Credentials grant type")
        }

        guard let refreshTokenString = request.data[OAuthRequestParameters.refreshToken]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'refresh_token' parameter")
        }

        guard let refreshToken = tokenManager.getRefreshToken(refreshTokenString),
            tokenAuthenticator.validateRefreshToken(refreshToken, clientID: clientID) else {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidGrant,
                                         description: "The refresh token is invalid")
        }

        let scopesString = request.data[OAuthRequestParameters.scope]?.string
        var scopesRequested = scopesString?.components(separatedBy: " ")

        if let scopes = scopesRequested {

            do {
                try scopeValidator.validateScope(clientID: clientID, scopes: scopes)
            } catch ScopeError.invalid {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained an invalid scope")
            } catch ScopeError.unknown {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained an unknown scope")
            }

            if let tokenScopes = refreshToken.scopes {
                for scope in scopes {
                    if !tokenScopes.contains(scope) {
                        return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                                 description: "Request contained elevated scopes")
                    }
                }
            } else {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained elevated scopes")
            }

            tokenManager.updateRefreshToken(refreshToken, scopes: scopes)
        } else {
            scopesRequested = refreshToken.scopes
        }

        let expiryTime = 3600
        let accessToken  = try tokenManager.generateAccessToken(clientID: clientID, userID: refreshToken.userID,
                                                                scopes: scopesRequested, expiryTime: expiryTime)

        return try tokenResponse(accessToken: accessToken, refreshToken: nil, expires: expiryTime, scope: scopesString)
    }

    private func handleClientCredentialsTokenRequest(_ request: Request) throws -> Response {
        guard let clientID = request.data[OAuthRequestParameters.clientID]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'client_id' parameter")
        }

        guard let clientSecret = request.data[OAuthRequestParameters.clientSecret]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'client_secret' parameter")
        }

        do {
            try clientValidator.authenticateClient(clientID: clientID, clientSecret: clientSecret,
                                                   grantType: .clientCredentials, checkConfidentialClient: true)
        } catch ClientError.unauthorized {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                     description: "Request had invalid client credentials", status: .unauthorized)
        } catch ClientError.notConfidential {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                     description: "You are not authorized to use the Client Credentials grant type")
        }

        let scopeString = request.data[OAuthRequestParameters.scope]?.string
        if let scopes = scopeString {
            do {
                try scopeValidator.validateScope(clientID: clientID, scopes: scopes.components(separatedBy: " "))
            } catch ScopeError.invalid {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained an invalid scope")
            } catch ScopeError.unknown {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained an unknown scope")
            }
        }

        let expiryTime = 3600
        let scopes = scopeString?.components(separatedBy: " ")
        let (access, refresh) = try tokenManager.generateAccessRefreshTokens(clientID: clientID, userID: nil,
                                                                             scopes: scopes,
                                                                             accessTokenExpiryTime: expiryTime)

        return try tokenResponse(accessToken: access, refreshToken: refresh, expires: expiryTime, scope: scopeString)
    }

    private func handleAuthCodeTokenRequest(_ request: Request) throws -> Response {
        guard let codeString = request.data[OAuthRequestParameters.code]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'code' parameter")
        }

        guard let redirectURI = request.data[OAuthRequestParameters.redirectURI]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'redirect_uri' parameter")
        }

        guard let clientID = request.data[OAuthRequestParameters.clientID]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'client_id' parameter")
        }

        do {
            try clientValidator.authenticateClient(clientID: clientID,
                                                   clientSecret: request.data[OAuthRequestParameters.clientSecret]?.string,
                                                   grantType: .authorization)
        } catch {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                     description: "Request had invalid client credentials", status: .unauthorized)
        }

        guard let code = codeManager.getCode(codeString),
            codeValidator.validateCode(code, clientID: clientID, redirectURI: redirectURI) else {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidGrant,
                                         description: "The code provided was invalid or expired, or the redirect URI did not match")
        }

        codeManager.codeUsed(code)

        let scopes = code.scopes
        let expiryTime = 3600

        let (access, refresh) = try tokenManager.generateAccessRefreshTokens(clientID: clientID, userID: code.userID,
                                                                             scopes: scopes,
                                                                             accessTokenExpiryTime: expiryTime)

        return try tokenResponse(accessToken: access, refreshToken: refresh, expires: Int(expiryTime),
                                 scope: scopes?.joined(separator: " "))
    }

    private func handlePasswordTokenRequest(_ request: Request) throws -> Response {
        guard let username = request.data[OAuthRequestParameters.usernname]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'username' parameter")
        }

        guard let password = request.data[OAuthRequestParameters.password]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'password' parameter")
        }

        guard let clientID = request.data[OAuthRequestParameters.clientID]?.string else {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                     description: "Request was missing the 'client_id' parameter")
        }

        do {
            try clientValidator.authenticateClient(clientID: clientID,
                                                   clientSecret: request.data[OAuthRequestParameters.clientSecret]?.string,
                                                   grantType: .password)
        } catch ClientError.unauthorized {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                     description: "Request had invalid client credentials", status: .unauthorized)
        } catch ClientError.notFirstParty {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                     description: "Password Credentials grant is not allowed")
        }

        let scopeString = request.data[OAuthRequestParameters.scope]?.string

        if let scopes = scopeString {
            do {
                try scopeValidator.validateScope(clientID: clientID, scopes: scopes.components(separatedBy: " "))
            } catch ScopeError.invalid {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained an invalid scope")
            } catch ScopeError.unknown {
                return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                         description: "Request contained an unknown scope")
            }
        }

        guard let userID = userManager.authenticateUser(username: username, password: password) else {
            log.warning("LOGIN WARNING: Invalid login attempt for user \(username)")
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidGrant,
                                     description: "Request had invalid credentials")
        }

        let expiryTime = 3600
        let scopes = scopeString?.components(separatedBy: " ")

        let (access, refresh) = try tokenManager.generateAccessRefreshTokens(clientID: clientID, userID: userID,
                                                                             scopes: scopes,
                                                                             accessTokenExpiryTime: expiryTime)

        return try tokenResponse(accessToken: access, refreshToken: refresh, expires: expiryTime, scope: scopeString)
    }

    private func tokenResponse(error: String, description: String, status: Status = .badRequest) throws -> Response {
        var json = JSON()
        try json.set(OAuthResponseParameters.error, error)
        try json.set(OAuthResponseParameters.errorDescription, description)

        return try createResponseForToken(status: status, json: json)
    }

    private func tokenResponse(accessToken: AccessToken, refreshToken: RefreshToken?,
                               expires: Int, scope: String?) throws -> Response {

        var json = JSON()
        try json.set(OAuthResponseParameters.tokenType, "bearer")
        try json.set(OAuthResponseParameters.expires, expires)
        try json.set(OAuthResponseParameters.accessToken, accessToken.tokenString)

        if let refreshToken = refreshToken {
            try json.set(OAuthResponseParameters.refreshToken, refreshToken.tokenString)
        }

        if let scope = scope {
            try json.set(OAuthResponseParameters.scope, scope)
        }

        return try createResponseForToken(status: .ok, json: json)
    }

    private func createResponseForToken(status: Status, json: JSON) throws -> Response {
        let response = try Response(status: status, json: json)

        response.headers[.pragma] = "no-cache"
        response.headers[.cacheControl] = "no-store"

        return response
    }
}
