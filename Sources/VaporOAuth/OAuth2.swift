import Vapor

public struct OAuth2: LifecycleHandler {
    let codeManager: CodeManager
    let tokenManager: TokenManager
    let clientRetriever: ClientRetriever
    let authorizeHandler: AuthorizeHandler
    let userManager: UserManager
    let validScopes: [String]?
    let resourceServerRetriever: ResourceServerRetriever
    let oAuthHelper: OAuthHelper
    let discoveryDocument: DiscoveryDocument?
    
    public init(
        codeManager: CodeManager = EmptyCodeManager(),
        tokenManager: TokenManager,
        clientRetriever: ClientRetriever,
        authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
        userManager: UserManager = EmptyUserManager(),
        validScopes: [String]? = nil,
        resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever(),
        oAuthHelper: OAuthHelper,
        discoveryDocument: DiscoveryDocument? = nil
    ) {
        self.codeManager = codeManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
        self.tokenManager = tokenManager
        self.userManager = userManager
        self.validScopes = validScopes
        self.resourceServerRetriever = resourceServerRetriever
        self.oAuthHelper = oAuthHelper
        self.discoveryDocument = discoveryDocument
    }
    
    public func didBoot(_ application: Application) throws {
        addRoutes(to: application)
        application.oAuthHelper = oAuthHelper
    }
    
    private func addRoutes(to app: Application) {
        let scopeValidator = ScopeValidator(validScopes: validScopes, clientRetriever: clientRetriever)
        let clientValidator = ClientValidator(
            clientRetriever: clientRetriever,
            scopeValidator: scopeValidator,
            environment: app.environment
        )
        
        let tokenHandler = TokenHandler(
            clientValidator: clientValidator,
            tokenManager: tokenManager,
            scopeValidator: scopeValidator,
            codeManager: codeManager,
            userManager: userManager,
            logger: app.logger
        )
        
        let tokenIntrospectionHandler = TokenIntrospectionHandler(
            clientValidator: clientValidator,
            tokenManager: tokenManager,
            userManager: userManager
        )
        
        let authorizeGetHandler = AuthorizeGetHandler(
            authorizeHandler: authorizeHandler,
            clientValidator: clientValidator
        )
        let authorizePostHandler = AuthorizePostHandler(
            tokenManager: tokenManager,
            codeManager: codeManager,
            clientValidator: clientValidator
        )
        
        let resourceServerAuthenticator = ResourceServerAuthenticator(resourceServerRetriever: resourceServerRetriever)
        
        // returning something like "Authenticate with GitHub page"
        app.get("oauth", "authorize", use: authorizeGetHandler.handleRequest)
        // pressing something like "Allow/Deny Access" button on "Authenticate with GitHub page". Returns a code.
        app.grouped(OAuthUser.guardMiddleware()).post("oauth", "authorize", use: authorizePostHandler.handleRequest)
        // client requesting access/refresh token with code from POST /authorize endpoint
        app.post("oauth", "token", use: tokenHandler.handleRequest)
        
        if let discoveryDocument = self.discoveryDocument {
            let discoveryDocumentHandler = DiscoveryDocumentHandler(discoveryDocument: discoveryDocument)
            app.get(".well-known", "openid-configuration", use: discoveryDocumentHandler.handleRequest)
        }
        
        let tokenIntrospectionAuthMiddleware = TokenIntrospectionAuthMiddleware(resourceServerAuthenticator: resourceServerAuthenticator)
        let resourceServerProtected = app.routes.grouped(tokenIntrospectionAuthMiddleware)
        resourceServerProtected.post("oauth", "token_info", use: tokenIntrospectionHandler.handleRequest)
    }
}
