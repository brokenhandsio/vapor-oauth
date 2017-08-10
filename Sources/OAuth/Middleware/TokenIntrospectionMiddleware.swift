import Vapor

struct TokenIntrospectionMiddleware: Middleware {

    let resourceServerAuthenticator: ResourceServerAuthenticator

    func respond(to request: Request, chainingTo next: Responder) throws -> Response {
        guard let password = request.auth.header?.basic else {
            throw Abort.unauthorized
        }

        try resourceServerAuthenticator.authenticate(credentials: password)

        return try next.respond(to: request)
    }
}
