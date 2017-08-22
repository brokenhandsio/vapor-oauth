import Vapor

public struct OAuth2TokenIntrospectionMiddleware: Middleware {

    let tokenIntrospectionEndpoint: String
    let requiredScopes: [String]?
    let client: ClientFactoryProtocol

    public init(tokenIntrospectionEndpoint: String, requiredScopes: [String]?, client: ClientFactoryProtocol) {
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.requiredScopes = requiredScopes
        self.client = client
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        Helper.setup(for: request, tokenIntrospectionEndpoint: tokenIntrospectionEndpoint, client: client)
        try request.oauth.assertScopes(requiredScopes)

        return try next.respond(to: request)
    }
}
