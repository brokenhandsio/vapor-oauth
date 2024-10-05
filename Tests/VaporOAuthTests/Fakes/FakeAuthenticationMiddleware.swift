import Vapor

@testable import VaporOAuth

struct FakeAuthenticationMiddleware: AsyncMiddleware {
    typealias User = OAuthUser

    private let allowedUsers: [OAuthUser]

    init(allowedUsers: [OAuthUser]) {
        self.allowedUsers = allowedUsers
    }

    func respond(to request: Vapor.Request, chainingTo next: Vapor.AsyncResponder) async throws -> Vapor.Response {
        if let basicAuth = request.headers.basicAuthorization,
            let user = allowedUsers.first(
                where: { $0.username == basicAuth.username && $0.password == basicAuth.password }
            )
        {
            request.auth.login(user)
        }
        return try await next.respond(to: request)
    }
}
