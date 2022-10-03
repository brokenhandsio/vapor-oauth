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
        environment: Environment = .testing
//        log: CapturingLogger? = nil,
//        sessions: FakeSessions? = nil
    ) throws -> Application {
        let app = Application(environment)
        app.middleware.use(app.sessions.middleware)

        app.lifecycle.use(
            Provider(
                codeManager: codeManager,
                tokenManager: tokenManager,
                clientRetriever: clientRetriever,
                authorizeHandler: authorizeHandler,
                userManager: userManager,
                validScopes: validScopes,
                resourceServerRetriever: resourceServerRetriever
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

//    static func getOAuthDroplet(codeManager: CodeManager = EmptyCodeManager(), tokenManager: TokenManager = StubTokenManager(), clientRetriever: ClientRetriever = FakeClientGetter(), userManager: UserManager = EmptyUserManager(), authorizeHandler: AuthorizeHandler = EmptyAuthorizationHandler(), validScopes: [String]? = nil, resourceServerRetriever: ResourceServerRetriever = EmptyResourceServerRetriever(), environment: Environment? = nil, log: CapturingLogger? = nil, sessions: FakeSessions? = nil) throws -> Droplet {
//        var config = Config([:])
//
//        if let environment = environment {
//            config.environment = environment
//        }
//
//        if let log = log {
//            config.addConfigurable(log: { (_) -> (CapturingLogger) in
//                return log
//            }, name: "capturing-log")
//            try config.set("droplet.log", "capturing-log")
//        }
//
//        let provider = VaporOAuth.Provider(codeManager: codeManager, tokenManager: tokenManager, clientRetriever: clientRetriever, authorizeHandler: authorizeHandler, userManager: userManager, validScopes: validScopes, resourceServerRetriever: resourceServerRetriever)
//
//        try config.addProvider(provider)
//
//        config.addConfigurable(middleware: SessionsMiddleware.init, name: "sessions")
//        try config.set("droplet.middleware", ["error", "sessions"])
//
//        if let sessions = sessions {
//            config.addConfigurable(sessions: { (_) -> (FakeSessions) in
//                return sessions
//            }, name: "fake")
//            try config.set("droplet.sessions", "fake")
//        }
//
//        return try Droplet(config)
//    }
//
//    static func getTokenRequestResponse(with drop: Droplet, grantType: String?, clientID: String?, clientSecret: String?, redirectURI: String? = nil, code: String? = nil, scope: String? = nil, username: String? = nil, password: String? = nil, refreshToken: String? = nil) throws -> Response {
//        let request = Request(method: .post, uri: "/oauth/token/")
//
//        var requestData = Node([:], in: nil)
//
//        if let grantType = grantType {
//            try requestData.set("grant_type", grantType)
//        }
//
//        if let clientID = clientID {
//            try requestData.set("client_id", clientID)
//        }
//
//        if let clientSecret = clientSecret {
//            try requestData.set("client_secret", clientSecret)
//        }
//
//        if let redirectURI = redirectURI {
//            try requestData.set("redirect_uri", redirectURI)
//        }
//
//        if let code = code {
//            try requestData.set("code", code)
//        }
//
//        if let scope = scope {
//            try requestData.set("scope", scope)
//        }
//
//        if let username = username {
//            try requestData.set("username", username)
//        }
//
//        if let password = password {
//            try requestData.set("password", password)
//        }
//
//        if let refreshToken = refreshToken {
//            try requestData.set("refresh_token", refreshToken)
//        }
//
//        request.formURLEncoded = requestData
//
//        let response = try drop.respond(to: request)
//
//        return response
//    }
//
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
//        sessionCookie: Cookie? = nil,
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

//        if let sessionCookie = sessionCookie {
//            authRequest.cookies.insert(sessionCookie)
//        }

//        if let sessionID = sessionID {
//            let customSessionCookie = Cookie(name: "vapor-session", value: sessionID)
//            authRequest.cookies.insert(customSessionCookie)
//        }

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/authorize?\(requestQuery)",
                    beforeRequest: { request in
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
