import Vapor

struct TokenIntrospectionAuthMiddleware: AsyncMiddleware {
    let resourceServerAuthenticator: ResourceServerAuthenticator

    func respond(to request: Request, chainingTo next: AsyncResponder) async throws -> Response {
        guard let basicAuthorization = request.headers.basicAuthorization else {
            throw Abort(.unauthorized)
        }

        try await resourceServerAuthenticator.authenticate(credentials: basicAuthorization)

        return try await next.respond(to: request)
    }
}
