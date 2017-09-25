import Vapor

public struct OAuth2TokenIntrospectionMiddleware: Middleware {

    let tokenIntrospectionEndpoint: String
    let requiredScopes: [String]?
    let client: ClientFactoryProtocol
    let resourceServerUsername: String
    let resourceServerPassword: String

    public init(tokenIntrospectionEndpoint: String, requiredScopes: [String]?, client: ClientFactoryProtocol,
                resourceServerUsername: String, resourceServerPassword: String) {
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.requiredScopes = requiredScopes
        self.client = client
        self.resourceServerUsername = resourceServerUsername
        self.resourceServerPassword = resourceServerPassword
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        Helper.setup(for: request, tokenIntrospectionEndpoint: tokenIntrospectionEndpoint, client: client,
                     resourceServerUsername: resourceServerUsername, resourceServerPassword: resourceServerPassword)
        try request.oauth.assertScopes(requiredScopes)

        return try next.respond(to: request)
    }
}
