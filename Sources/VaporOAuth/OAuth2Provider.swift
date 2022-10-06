import Vapor

public struct OAuth2Provider {
    let tokenManager: TokenManager
    let userManager: UserManager
    let authorizePostHandler: AuthorizePostHandler
    let authorizeGetHandler: AuthorizeGetHandler
    let tokenHandler: TokenHandler
    let tokenIntrospectionHandler: TokenIntrospectionHandler
    let resourceServerAuthenticator: ResourceServerAuthenticator
    let authenticateUser: (Request) async throws -> Void

    private let app: Application

    init(
        codeManager: CodeManager,
        tokenManager: TokenManager,
        clientRetriever: ClientRetriever,
        authorizeHandler: AuthorizeHandler,
        userManager: UserManager,
        validScopes: [String]?,
        resourceServerRetriever: ResourceServerRetriever,
        authenticateUser: @escaping (Request) async throws -> Void,
        app: Application
    ) {
        self.app = app
        self.tokenManager = tokenManager
        self.userManager = userManager
        self.authenticateUser = authenticateUser

        resourceServerAuthenticator = ResourceServerAuthenticator(resourceServerRetriever: resourceServerRetriever)
        let scopeValidator = ScopeValidator(validScopes: validScopes, clientRetriever: clientRetriever)
        let clientValidator = ClientValidator(clientRetriever: clientRetriever, scopeValidator: scopeValidator, environment: app.environment)
        authorizePostHandler = AuthorizePostHandler(tokenManager: tokenManager, codeManager: codeManager, clientValidator: clientValidator)
        authorizeGetHandler = AuthorizeGetHandler(authorizeHandler: authorizeHandler, clientValidator: clientValidator)
        tokenHandler = TokenHandler(
            clientValidator: clientValidator,
            tokenManager: tokenManager,
            scopeValidator: scopeValidator,
            codeManager: codeManager,
            userManager: userManager,
            logger: app.logger
        )
        tokenIntrospectionHandler = TokenIntrospectionHandler(clientValidator: clientValidator, tokenManager: tokenManager,
                                                              userManager: userManager)
    }

    func addRoutes() {
        // returning something like "Authenticate with GitHub page"
        app.get("oauth", "authorize", use: authorizeGetHandler.handleRequest)
        // pressing something like "Allow/Deny Access" button on "Authenticate with GitHub page". Returns a code.
        app.grouped(AuthorizePostMiddleware(authenticateUser: authenticateUser))
            .post("oauth", "authorize", use: authorizePostHandler.handleRequest)
        // client requesting access/refresh token with code from POST /authorize endpoint
        app.post("oauth", "token", use: tokenHandler.handleRequest)

        let tokenIntrospectionAuthMiddleware = TokenIntrospectionAuthMiddleware(resourceServerAuthenticator: resourceServerAuthenticator)
        let resourceServerProtected = app.routes.grouped(tokenIntrospectionAuthMiddleware)
        resourceServerProtected.post("oauth", "token_info", use: tokenIntrospectionHandler.handleRequest)
    }
}

struct AuthorizePostMiddleware: AsyncMiddleware {
    private let authenticateUser: (Request) async throws -> Void

    init(authenticateUser: @escaping (Request) async throws -> Void) {
        self.authenticateUser = authenticateUser
    }

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        try await authenticateUser(request)
        return try await next.respond(to: request)
    }
}

extension Application {
    struct Key: StorageKey {
        typealias Value = OAuth2Provider
    }

    public var oAuth2Provider: OAuth2Provider {
        get {
            guard let oauth = self.storage[Key.self] else {
                fatalError("OAuth2Provider not implemented. Use Application.oAuth2Provider = ...")
            }
            return oauth
        }
        set {
            self.storage[Key.self] = newValue
        }
    }
}
