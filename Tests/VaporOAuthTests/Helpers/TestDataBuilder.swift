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
        logger: CapturingLogger? = nil,
        sessions: FakeSessions? = nil,
        registeredUsers: [OAuthUser] = []
    ) throws -> Application {
        let app = Application(environment)

        if let sessions = sessions {
            app.sessions.use { _ in sessions }
        }

        app.middleware.use(FakeAuthenticationMiddleware(allowedUsers: registeredUsers))
        app.middleware.use(app.sessions.middleware)

        app.lifecycle.use(
            OAuth2(
                codeManager: codeManager,
                tokenManager: tokenManager,
                clientRetriever: clientRetriever,
                authorizeHandler: authorizeHandler,
                userManager: userManager,
                validScopes: validScopes,
                resourceServerRetriever: resourceServerRetriever,
                oAuthHelper: .local(
                    tokenAuthenticator: nil,
                    userManager: nil,
                    tokenManager: nil
                )
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

    static func getTokenRequestResponse(
        with app: Application,
        grantType: String?,
        clientID: String?,
        clientSecret: String?,
        redirectURI: String? = nil,
        code: String? = nil,
        scope: String? = nil,
        username: String? = nil,
        password: String? = nil,
        refreshToken: String? = nil,
        deviceCode: String? = nil
    ) async throws -> XCTHTTPResponse {
        struct RequestData: Content {
            var grantType: String?
            var clientID: String?
            var clientSecret: String?
            var redirectURI: String?
            var code: String?
            var scope: String?
            var username: String?
            var password: String?
            var refreshToken: String?
            var deviceCode: String?
            
            enum CodingKeys: String, CodingKey {
                case username, password, scope, code
                case grantType = "grant_type"
                case clientID = "client_id"
                case clientSecret = "client_secret"
                case redirectURI = "redirect_uri"
                case refreshToken = "refresh_token"
                case deviceCode = "device_code"
            }
        }

        let requestData = RequestData(
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI,
            code: code,
            scope: scope,
            username: username,
            password: password,
            refreshToken: refreshToken,
            deviceCode: deviceCode
        )

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/token/",
                    beforeRequest: { request in
                        try request.content.encode(requestData, as: .urlEncodedForm)
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
        csrfToken: String?,
        user: OAuthUser?,
        sessionCookie: HTTPCookies? = nil,
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
        }

        var requestBody = RequestBody()
        requestBody.applicationAuthorized = approve
        requestBody.csrfToken = csrfToken

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/authorize?\(requestQuery)",
                    beforeRequest: { request in
                        if let sessionID = sessionID {
                            request.headers.cookie = ["vapor-session": .init(string: sessionID)]
                        }
                        if let sessionCookie = sessionCookie {
                            request.headers.cookie = sessionCookie
                        }
                        try request.content.encode(requestBody, as: .urlEncodedForm)

                        if let user = user {
                            request.headers.basicAuthorization = .init(
                                username: user.username,
                                password: user.password
                            )
                        }
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
