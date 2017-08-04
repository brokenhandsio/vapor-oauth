import HTTP

public struct OAuth2ScopeMiddleware: Middleware {
    let requiredScopes: [String]?

    public init(requiredScopes: [String]?) {
        self.requiredScopes = requiredScopes
    }

    public func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        try request.oauth.assertScopes(requiredScopes)

        return try next.respond(to: request)
    }
}
