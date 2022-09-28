import Vapor

public struct OAuth2TokenIntrospectionMiddleware: AsyncMiddleware {

    let tokenIntrospectionEndpoint: String
    let requiredScopes: [String]?
    let client: Client
    let resourceServerUsername: String
    let resourceServerPassword: String

    public init(tokenIntrospectionEndpoint: String, requiredScopes: [String]?, client: Client,
                resourceServerUsername: String, resourceServerPassword: String) {
        self.tokenIntrospectionEndpoint = tokenIntrospectionEndpoint
        self.requiredScopes = requiredScopes
        self.client = client
        self.resourceServerUsername = resourceServerUsername
        self.resourceServerPassword = resourceServerPassword
    }

    public func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
//        Helper.setup(for: request, tokenIntrospectionEndpoint: tokenIntrospectionEndpoint, client: client,
//                     resourceServerUsername: resourceServerUsername, resourceServerPassword: resourceServerPassword)
//        try await request.oauth.assertScopes(requiredScopes)

        return try await next.respond(to: request)
    }
}
