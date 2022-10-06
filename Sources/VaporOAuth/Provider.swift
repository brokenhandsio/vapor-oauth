import Vapor

public final class Provider: LifecycleHandler {
    let codeManager: CodeManager
    let tokenManager: TokenManager
    let clientRetriever: ClientRetriever
    let authorizeHandler: AuthorizeHandler
    let userManager: UserManager
    let validScopes: [String]?
    let resourceServerRetriever: ResourceServerRetriever
    let authenticateUser: (Request) async throws -> Void

    public init(codeManager: CodeManager = EmptyCodeManager(), tokenManager: TokenManager,
                clientRetriever: ClientRetriever, authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
                userManager: UserManager = EmptyUserManager(), validScopes: [String]? = nil,
                resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever(),
                authenticateUser: @escaping (Request) async throws -> Void) {

        self.codeManager = codeManager
        self.tokenManager = tokenManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
        self.userManager = userManager
        self.validScopes = validScopes
        self.resourceServerRetriever = resourceServerRetriever
        self.authenticateUser = authenticateUser
    }

    public func didBoot(_ application: Application) throws {
        let provider = OAuth2Provider(
            codeManager: codeManager,
            tokenManager: tokenManager,
            clientRetriever: clientRetriever,
            authorizeHandler: authorizeHandler,
            userManager: userManager,
            validScopes: validScopes,
            resourceServerRetriever: resourceServerRetriever,
            authenticateUser: authenticateUser,
            app: application
        )

        provider.addRoutes()
    }
}
