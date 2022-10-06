@testable import VaporOAuth
import XCTVapor
import Vapor

class TestDataBuilder {
    static func getOAuth2Application(
        codeManager: CodeManager = EmptyCodeManager(),
        tokenManager: TokenManager = StubTokenManager(),
        clientRetriever: ClientRetriever = FakeClientGetter(),
        userManager: UserManager = EmptyUserManager(),
        authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(),
        validScopes: [String]? = nil,
        resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever(),
        environment: Environment = .testing,
        authenticateUser: @escaping (Request) async throws -> Void = { req in req.auth.login(TestDataBuilder.anyOAuthUser()) },
//        log: CapturingLogger? = nil,
        sessions: FakeSessions? = nil
    ) throws -> Application {
        let app = Application(environment)

        if let sessions = sessions {
            app.sessions.use { _ in sessions }
        }

        app.middleware.use(app.sessions.middleware)

        app.lifecycle.use(
            Provider(
                codeManager: codeManager,
                tokenManager: tokenManager,
                clientRetriever: clientRetriever,
                authorizeHandler: authorizeHandler,
                userManager: userManager,
                validScopes: validScopes,
                resourceServerRetriever: resourceServerRetriever,
                authenticateUser: authenticateUser
            )
        )

        do {
            _ = try app.testable()
        } catch {
            app.shutdown()
            throw error
        }

        return app
    }

    static func getAuthRequestResponse(
        with app: Application,
        responseType: String?,
        clientID: String?,
        redirectURI: String?,
        scope: String?,
        state: String?
    ) async throws -> XCTHTTPResponse {

        var queries: [String] = []

        if let responseType = responseType {
            queries.append("response_type=\(responseType)")
        }

        if let clientID = clientID {
            queries.append("client_id=\(clientID)")
        }

        if let redirectURI = redirectURI {
            queries.append("redirect_uri=\(redirectURI)")
        }

        if let scope = scope {
            queries.append("scope=\(scope)")
        }

        if let state = state {
            queries.append("state=\(state)")
        }

        let requestQuery = queries.joined(separator: "&")

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(.GET, "/oauth/authorize?\(requestQuery)", afterResponse: { response in
                    continuation.resume(returning: response)
                })
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    static func getAuthResponseResponse(
        with app: Application,
        approve: Bool?,
        clientID: String?,
        redirectURI: String?,
        responseType: String?,
        scope: String?,
        state: String?,
        user: OAuthUser?,
        csrfToken: String?,
        sessionCookie: HTTPCookie? = nil,
        sessionID: String? = nil
    ) async throws -> XCTHTTPResponse {
        var queries: [String] = []

        if let clientID = clientID {
            queries.append("client_id=\(clientID)")
        }

        if let redirectURI = redirectURI {
            queries.append("redirect_uri=\(redirectURI)")
        }

        if let state = state {
            queries.append("state=\(state)")
        }

        if let scope = scope {
            queries.append("scope=\(scope)")
        }

        if let responseType = responseType {
            queries.append("response_type=\(responseType)")
        }

        let requestQuery = queries.joined(separator: "&")

        struct RequestBody: Encodable {
            var applicationAuthorized: Bool?
            var csrfToken: String?
            var authAuthenticated: OAuthUser?

            enum CodingKeys: String, CodingKey {
                case applicationAuthorized, csrfToken
                case authAuthenticated = "auth-authenticated"
            }
        }

        var requestBody = RequestBody()
        requestBody.applicationAuthorized = approve
        requestBody.csrfToken = csrfToken
        requestBody.authAuthenticated = user

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/authorize?\(requestQuery)",
                    beforeRequest: { request in
                        if let sessionID = sessionID {
                            request.headers.cookie = ["vapor-session": .init(string: sessionID)]
                        }
                        try request.content.encode(requestBody, as: .urlEncodedForm)
                    },
                    afterResponse: { response in
                        continuation.resume(returning: response)
                    }
                )
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

    static let anyUserID: String = "12345-asbdsadi"
    static func anyOAuthUser() -> OAuthUser {
        return OAuthUser(
            userID: TestDataBuilder.anyUserID,
            username: "hansolo",
            emailAddress: "han.solo@therebelalliance.com",
            password: "leia"
        )
    }
}
