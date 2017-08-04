import Vapor
import HTTP
import AuthProvider
import Crypto

struct OAuth2Provider {

    let codeManager: CodeManager
    let tokenManager: TokenManager
    let clientRetriever: ClientRetriever
    let authorizeHandler: AuthorizeHandler
    let userManager: UserManager
    let log: LogProtocol
    let tokenAuthenticator: TokenAuthenticator
    let authorizePostHandler: AuthorizePostHandler
    let scopeValidator: ScopeValidator
    let clientValidator: ClientValidator

    init(codeManager: CodeManager, tokenManager: TokenManager, clientRetriever: ClientRetriever,
         authorizeHandler: AuthorizeHandler, userManager: UserManager, validScopes: [String]?,
         environment: Environment, log: LogProtocol) {
        self.codeManager = codeManager
        self.tokenManager = tokenManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
        self.userManager = userManager
        self.log = log

        tokenAuthenticator = TokenAuthenticator()
        scopeValidator = ScopeValidator(validScopes: validScopes, clientRetriever: clientRetriever)
        clientValidator = ClientValidator(clientRetriever: clientRetriever, scopeValidator: scopeValidator, environment: environment)
        authorizePostHandler = AuthorizePostHandler(tokenManager: tokenManager, codeManager: codeManager, clientValidator: clientValidator)
    }

    func addRoutes(to router: RouteBuilder) {
        router.get("oauth", "authorize", handler: authHandler)
        router.post("oauth", "authorize", handler: authorizePostHandler.handleRequest)
        router.post("oauth", "token", handler: tokenPostHandler)
    }

    func authHandler(request: Request) throws -> ResponseRepresentable {

        guard let clientID = request.query?[OAuthRequestParameters.clientID]?.string else {
            return try authorizeHandler.handleAuthorizationError(.invalidClientID)
        }

        guard let redirectURIString = request.query?[OAuthRequestParameters.redirectURI]?.string else {
            return try authorizeHandler.handleAuthorizationError(.invalidRedirectURI)
        }

        let scopes: [String]

        if let scopeQuery = request.query?[OAuthRequestParameters.scope]?.string {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = []
        }

        let state = request.query?[OAuthRequestParameters.state]?.string

        guard let responseType = request.query?[OAuthRequestParameters.responseType]?.string else {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                       errorDescription: "Request+was+missing+the+response_type+parameter", state: state)
        }

        guard responseType == ResponseType.code || responseType == ResponseType.token else {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                       errorDescription: "invalid+response+type", state: state)
        }

        do {
            try clientValidator.validateClient(clientID: clientID, responseType: responseType,
                                               redirectURI: redirectURIString, scopes: scopes)
        } catch AuthorizationError.invalidClientID {
            return try authorizeHandler.handleAuthorizationError(.invalidClientID)
        } catch AuthorizationError.invalidRedirectURI {
            return try authorizeHandler.handleAuthorizationError(.invalidRedirectURI)
        } catch ScopeError.unknown {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+unknown", state: state)
        } catch ScopeError.invalid {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+invalid", state: state)
        } catch AuthorizationError.confidentialClientTokenGrant {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                       errorDescription: "token+grant+disabled+for+confidential+clients", state: state)
        } catch AuthorizationError.httpRedirectURI {
            return try authorizeHandler.handleAuthorizationError(.httpRedirectURI)
        }

        let redirectURI = URIParser.shared.parse(bytes: redirectURIString.makeBytes())

        let csrfToken = try Random.bytes(count: 32).hexString

        guard let session = request.session else {
            throw Abort.badRequest
        }

        try session.data.set(SessionData.csrfToken, csrfToken)

        return try authorizeHandler.handleAuthorizationRequest(request, responseType: responseType, clientID: clientID,
                                                               redirectURI: redirectURI, scope: scopes, state: state,
                                                               csrfToken: csrfToken)
    }

    func tokenPostHandler(request: Request) throws -> Response {
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
            try authenticateClient(clientID: clientID, clientSecret: clientSecret,
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
            try authenticateClient(clientID: clientID, clientSecret: clientSecret,
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
            try authenticateClient(clientID: clientID,
                                   clientSecret: request.data[OAuthRequestParameters.clientSecret]?.string,
                                   grantType: .authorization)
        } catch {
            return try tokenResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                     description: "Request had invalid client credentials", status: .unauthorized)
        }

        guard let code = codeManager.getCode(codeString),
            validateCode(code, clientID: clientID, redirectURI: redirectURI) else {
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
            try authenticateClient(clientID: clientID,
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

    private func validateCode(_ code: OAuthCode, clientID: String, redirectURI: String) -> Bool {
        guard code.clientID == clientID else {
            return false
        }

        guard code.expiryDate >= Date() else {
            return false
        }

        guard code.redirectURI == redirectURI else {
            return false
        }

        return true
    }

    private func authenticateClient(clientID: String, clientSecret: String?,
                                    grantType: OAuthFlowType, checkConfidentialClient: Bool = false) throws {
        guard let client = clientRetriever.getClient(clientID: clientID) else {
            throw ClientError.unauthorized
        }

        guard clientSecret == client.clientSecret else {
            throw ClientError.unauthorized
        }

        guard client.allowedGrantTypes?.contains(grantType) ?? true else {
            throw Abort(.forbidden)
        }

        if grantType == .password {
            guard client.firstParty else {
                throw ClientError.notFirstParty
            }
        }

        if checkConfidentialClient {
            guard client.confidentialClient ?? false else {
                throw ClientError.notConfidential
            }
        }
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

    private func createErrorResponse(redirectURI: String, errorType: String, errorDescription: String,
                                     state: String?) -> Response {
        var redirectString = "\(redirectURI)?error=\(errorType)&error_description=\(errorDescription)"

        if let state = state {
            redirectString += "&state=\(state)"
        }

        return Response(redirect: redirectString)
    }
}
