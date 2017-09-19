import Vapor

public final class Provider: Vapor.Provider {
    public static let repositoryName = "vapor-oauth"

    let codeManager: CodeManager
    let tokenManager: TokenManager
    let clientRetriever: ClientRetriever
    let authorizeHandler: AuthorizeHandler
    let userManager: UserManager
    let validScopes: [String]?
    let resourceServerRetriever: ResourceServerRetriever

    public init(config: Config) throws {
        throw OAuthProviderError.configInitUnavailble
    }

    public init(codeManager: CodeManager = EmptyCodeManager(), tokenManager: TokenManager,
                clientRetriever: ClientRetriever, authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
                userManager: UserManager = EmptyUserManager(), validScopes: [String]? = nil,
                resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever()) {

        self.codeManager = codeManager
        self.tokenManager = tokenManager
        self.clientRetriever = clientRetriever
        self.authorizeHandler = authorizeHandler
        self.userManager = userManager
        self.validScopes = validScopes
        self.resourceServerRetriever = resourceServerRetriever
    }

    public func boot(_ config: Config) throws { }

    public func boot(_ drop: Droplet) throws {
        let log = try drop.config.resolveLog()
        let provider = OAuth2Provider(codeManager: codeManager, tokenManager: tokenManager,
                                      clientRetriever: clientRetriever, authorizeHandler: authorizeHandler,
                                      userManager: userManager, validScopes: validScopes,
                                      resourceServerRetriever: resourceServerRetriever,
                                      environment: drop.config.environment, log: log)

        provider.addRoutes(to: drop)

        Request.oauthProvider = provider
    }

    public func beforeRun(_ drop: Droplet) throws { }
}

public enum OAuthProviderError: Error, CustomStringConvertible {
    case configInitUnavailble

    public var description: String {
        switch self {
        case .configInitUnavailble:
            return "The OAuth Provider cannot be created with a Config and must be created manually"
        }
    }
}
