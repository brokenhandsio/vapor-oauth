import Vapor
import HTTP
import AuthProvider

struct OAuth2Provider {

    let codeManager: CodeManager
    let tokenManager: TokenManager
    let clientRetriever: ClientRetriever
    let userManager: UserManager
    let log: LogProtocol
    let scopeValidator: ScopeValidator
    let clientValidator: ClientValidator
    let authorizePostHandler: AuthorizePostHandler
    let authorizeGetHandler: AuthorizeGetHandler
    let tokenHandler: TokenHandler
    let tokenIntrospectionHandler: TokenIntrospectionHandler

    init(codeManager: CodeManager, tokenManager: TokenManager, clientRetriever: ClientRetriever,
         authorizeHandler: AuthorizeHandler, userManager: UserManager, validScopes: [String]?,
         environment: Environment, log: LogProtocol) {
        self.codeManager = codeManager
        self.tokenManager = tokenManager
        self.clientRetriever = clientRetriever
        self.userManager = userManager
        self.log = log

        scopeValidator = ScopeValidator(validScopes: validScopes, clientRetriever: clientRetriever)
        clientValidator = ClientValidator(clientRetriever: clientRetriever, scopeValidator: scopeValidator, environment: environment)
        authorizePostHandler = AuthorizePostHandler(tokenManager: tokenManager, codeManager: codeManager, clientValidator: clientValidator)
        authorizeGetHandler = AuthorizeGetHandler(authorizeHandler: authorizeHandler, clientValidator: clientValidator)
        tokenHandler = TokenHandler(clientValidator: clientValidator, tokenManager: tokenManager, scopeValidator: scopeValidator,
                                    codeManager: codeManager, userManager: userManager, log: log)
        tokenIntrospectionHandler = TokenIntrospectionHandler(clientValidator: clientValidator, tokenManager: tokenManager)

    }

    func addRoutes(to router: RouteBuilder) {
        router.get("oauth", "authorize", handler: authorizeGetHandler.handleRequest)
        router.post("oauth", "authorize", handler: authorizePostHandler.handleRequest)
        router.post("oauth", "token", handler: tokenHandler.handleRequest)
        router.post("oauth", "token_info", handler: tokenIntrospectionHandler.handleRequest)
    }

}
