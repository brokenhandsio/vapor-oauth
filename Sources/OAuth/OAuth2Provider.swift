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
    let environment: Environment
    let log: LogProtocol
    let tokenAuthenticator: TokenAuthenticator
    let validScopes: [String]?

    init(codeManager: CodeManager, tokenManager: TokenManager, clientRetriever: ClientRetriever,
         authorizeHandler: AuthorizeHandler, userManager: UserManager, validScopes: [String]?,
         environment: Environment, log: LogProtocol) {
        self.codeManager = codeManager
        self.tokenManager = tokenManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
        self.userManager = userManager
        self.validScopes = validScopes
        self.environment = environment
        self.log = log

        tokenAuthenticator = TokenAuthenticator()
    }

    func addRoutes(to router: RouteBuilder) {
        router.get("oauth", "authorize", handler: authHandler)
        router.post("oauth", "authorize", handler: authPostHandler)
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
            try validateClient(clientID: clientID, responseType: responseType,
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

    struct AuthorizePostRequest {
        let user: OAuthUser
        let userID: Identifier
        let redirectURIBaseString: String
        let approveApplication: Bool
        let clientID: String
        let responseType: String
        let csrfToken: String
        let scopes: [String]?
    }

    private func validateAuthPostRequest(_ request: Request) throws -> AuthorizePostRequest {
        guard let user = request.auth.authenticated(OAuthUser.self) else {
            throw Abort.unauthorized
        }

        guard let userID = user.id else {
            throw Abort.unauthorized
        }

        guard let redirectURIBaseString = request.query?[OAuthRequestParameters.redirectURI]?.string else {
            throw Abort.badRequest
        }

        guard let approveApplication = request.data[OAuthRequestParameters.applicationAuthorized]?.bool else {
            throw Abort.badRequest
        }

        guard let clientID = request.query?[OAuthRequestParameters.clientID]?.string else {
            throw Abort.badRequest
        }

        guard let responseType = request.query?[OAuthRequestParameters.responseType]?.string else {
            throw Abort.badRequest
        }

        guard let csrfToken = request.data[OAuthRequestParameters.csrfToken]?.string else {
            throw Abort.badRequest
        }

        let scopes: [String]?

        if let scopeQuery = request.query?[OAuthRequestParameters.scope]?.string {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = nil
        }

        return AuthorizePostRequest(user: user, userID: userID, redirectURIBaseString: redirectURIBaseString,
                                    approveApplication: approveApplication, clientID: clientID,
                                    responseType: responseType, csrfToken: csrfToken, scopes: scopes)
    }

    func authPostHandler(request: Request) throws -> ResponseRepresentable {
        let requestObject = try validateAuthPostRequest(request)
        var redirectURI = requestObject.redirectURIBaseString

        do {
            try validateClient(clientID: requestObject.clientID, responseType: requestObject.responseType,
                               redirectURI: requestObject.redirectURIBaseString, scopes: requestObject.scopes)
        } catch is AbortError {
            throw Abort(.forbidden)
        } catch {
            throw Abort.badRequest
        }

        guard let session = request.session else {
            throw Abort.badRequest
        }

        guard session.data[SessionData.csrfToken]?.string == requestObject.csrfToken else {
            throw Abort.badRequest
        }

        if requestObject.approveApplication {
            if requestObject.responseType == ResponseType.token {
                let accessToken = try tokenManager.generateAccessToken(clientID: requestObject.clientID,
                                                                       userID: requestObject.userID,
                                                                       scopes: requestObject.scopes, expiryTime: 3600)
                redirectURI += "#token_type=bearer&access_token=\(accessToken.tokenString)&expires_in=3600"
            } else if requestObject.responseType == ResponseType.code {
                let generatedCode = try codeManager.generateCode(userID: requestObject.userID,
                                                                 clientID: requestObject.clientID,
                                                                 redirectURI: requestObject.redirectURIBaseString,
                                                                 scopes: requestObject.scopes)
                redirectURI += "?code=\(generatedCode)"
            } else {
                redirectURI += "?error=invalid_request&error_description=unknown+response+type"
            }
        } else {
            redirectURI += "?error=access_denied&error_description=user+denied+the+request"
        }

        if let requestedScopes = requestObject.scopes {
            if !requestedScopes.isEmpty {
                redirectURI += "&scope=\(requestedScopes.joined(separator: "+"))"
            }
        }

        if let state = request.query?[OAuthRequestParameters.state]?.string {
            redirectURI += "&state=\(state)"
        }

        return Response(redirect: redirectURI)
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
                try validateScope(clientID: clientID, scopes: scopes)
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
                try validateScope(clientID: clientID, scopes: scopes.components(separatedBy: " "))
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
                try validateScope(clientID: clientID, scopes: scopes.components(separatedBy: " "))
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

    private func validateScope(clientID: String, scopes: [String]?) throws {
        if let requestedScopes = scopes {
            let providerScopes = validScopes ?? []

            if !providerScopes.isEmpty {
                for scope in requestedScopes {
                    guard providerScopes.contains(scope) else {
                        throw ScopeError.unknown
                    }
                }
            }

            let client = clientRetriever.getClient(clientID: clientID)
            if let clientScopes = client?.validScopes {
                for scope in requestedScopes {
                    guard clientScopes.contains(scope) else {
                        throw ScopeError.invalid
                    }
                }
            }
        }
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

    private func validateClient(clientID: String, responseType: String, redirectURI: String, scopes: [String]?) throws {
        guard let client = clientRetriever.getClient(clientID: clientID) else {
            throw AuthorizationError.invalidClientID
        }

        if client.confidentialClient ?? false {
            guard responseType == ResponseType.code else {
                throw AuthorizationError.confidentialClientTokenGrant
            }
        }

        guard client.validateRedirectURI(redirectURI) else {
            throw AuthorizationError.invalidRedirectURI
        }

        if responseType == ResponseType.code {
            guard client.allowedGrantTypes?.contains(.authorization) ?? true else {
                throw Abort(.forbidden)
            }
        } else {
            guard client.allowedGrantTypes?.contains(.implicit) ?? true else {
                throw Abort(.forbidden)
            }
        }

        try validateScope(clientID: clientID, scopes: scopes)

        let redirectURI = URIParser.shared.parse(bytes: redirectURI.makeBytes())

        if environment == .production {
            if redirectURI.scheme != "https" {
                throw AuthorizationError.httpRedirectURI
            }
        }
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
