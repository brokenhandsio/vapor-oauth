import XCTVapor

@testable import VaporOAuth

class AuthCodeResourceServerTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var capturingAuthouriseHandler: CapturingAuthoriseHandler!
    var fakeTokenManager: FakeTokenManager!
    let newClientID = "the-client"
    let clientSecret = "the-secret"
    let redirectURI = "https://brokenhands.io/callback"
    let scope = "user"
    let scope2 = "email"
    let userID = "user-id"
    let username = "han"
    let email = "han.solo@therebelalliance.com"
    var newUser: OAuthUser!

    var resourceApp: Application!

    // MARK: - Overrides

    override func setUp() async throws {
        let newClient = OAuthClient(
            clientID: newClientID,
            redirectURIs: [redirectURI],
            clientSecret: clientSecret,
            validScopes: [scope, scope2],
            confidential: true,
            firstParty: true,
            allowedGrantType: .authorization
        )

        let fakeCodeManager = FakeCodeManager()
        let clientRetriever = StaticClientRetriever(clients: [newClient])
        let fakeUserManager = FakeUserManager()
        fakeTokenManager = FakeTokenManager()
        capturingAuthouriseHandler = CapturingAuthoriseHandler()

        newUser = OAuthUser(userID: userID, username: username, emailAddress: email, password: "leia")
        fakeUserManager.users.append(newUser)

        let oauthProvider = OAuth2(
            codeManager: fakeCodeManager,
            tokenManager: fakeTokenManager,
            clientRetriever: clientRetriever,
            authorizeHandler: capturingAuthouriseHandler,
            userManager: fakeUserManager,
            validScopes: [scope, scope2],
            oAuthHelper: .local(
                tokenAuthenticator: TokenAuthenticator(),
                userManager: fakeUserManager,
                tokenManager: fakeTokenManager
            )
        )

        app = Application(.testing)

        app.middleware.use(FakeAuthenticationMiddleware(allowedUsers: [newUser]))
        app.middleware.use(app.sessions.middleware)

        app.lifecycle.use(oauthProvider)

        let resourceController = TestResourceController()
        try app.routes.register(collection: resourceController)

        do {
            _ = try app.testable(method: .running)
        } catch {
            app.shutdown()
            throw error
        }
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    // MARK: - Tests
    // func testThatClientCanAccessResourceServerWithValidAuthCodeToken() async throws {
    //     // Get Auth Code
    //     let state = "jfeiojo382497329"
    //     let responseType = "code"
    //     let response = try await TestDataBuilder.getAuthRequestResponse(
    //         with: app,
    //         responseType: responseType,
    //         clientID: newClientID,
    //         redirectURI: redirectURI,
    //         scope: "\(scope)+\(scope2)",
    //         state: state
    //     )

    //     guard let cookie = response.headers.setCookie else {
    //         XCTFail()
    //         return
    //     }

    //     XCTAssertEqual(capturingAuthouriseHandler.responseType, responseType)
    //     XCTAssertEqual(capturingAuthouriseHandler.clientID, newClientID)
    //     XCTAssertEqual(capturingAuthouriseHandler.redirectURI, "\(redirectURI)")
    //     XCTAssertEqual(capturingAuthouriseHandler.scope?.count, 2)
    //     XCTAssertTrue(capturingAuthouriseHandler.scope?.contains(scope) ?? false)
    //     XCTAssertTrue(capturingAuthouriseHandler.scope?.contains(scope2) ?? false)
    //     XCTAssertEqual(capturingAuthouriseHandler.state, state)
    //     XCTAssertEqual(response.status, .ok)

    //     let codeResponse = try await TestDataBuilder.getAuthResponseResponse(
    //         with: app,
    //         approve: true,
    //         clientID: newClientID,
    //         redirectURI: redirectURI,
    //         responseType: responseType,
    //         scope: "\(scope)+\(scope2)",
    //         state: state,
    //         csrfToken: capturingAuthouriseHandler.csrfToken,
    //         user: newUser,
    //         sessionCookie: cookie
    //     )

    //     guard let newLocation = codeResponse.headers.location?.value else {
    //         XCTFail("Expected location header in response.")
    //         return
    //     }

    //     let codeRedirectURI = URI(string: newLocation)

    //     guard let query = codeRedirectURI.query else {
    //         XCTFail()
    //         return
    //     }

    //     let queryParts = query.components(separatedBy: "&")

    //     var codePart: String?

    //     for queryPart in queryParts {
    //         if queryPart.hasPrefix("code=") {
    //             let codeStartIndex = queryPart.index(queryPart.startIndex, offsetBy: 5)
    //             codePart = String(queryPart[codeStartIndex...])
    //         }
    //     }

    //     guard let codeFound = codePart else {
    //         XCTFail()
    //         return
    //     }

    //     print("Code was \(codeFound)")

    //     // Get Token

    //     let tokenResponse = try await TestDataBuilder.getTokenRequestResponse(
    //         with: app,
    //         grantType: "authorization_code",
    //         clientID: newClientID,
    //         clientSecret: clientSecret,
    //         redirectURI: redirectURI,
    //         code: codeFound
    //     )

    //     let tokenReponseData = try JSONDecoder().decode(SuccessResponse.self, from: tokenResponse.body)

    //     print("Token response was \(tokenResponse)")

    //     guard let token = tokenReponseData.accessToken else {
    //         XCTFail()
    //         return
    //     }

    //     guard let refreshToken = tokenReponseData.refreshToken else {
    //         XCTFail()
    //         return
    //     }

    //     // Get resource
    //     try app.test(.GET, "/protected", beforeRequest: { req in
    //         req.headers.bearerAuthorization = BearerAuthorization(token: token)
    //     }, afterResponse: { protectedResponse in
    //         XCTAssertEqual(protectedResponse.status, .ok)
    //     })

    //     // Get new token
    //     let tokenRefreshResponse = try await TestDataBuilder.getTokenRequestResponse(
    //         with: app,
    //         grantType: "refresh_token",
    //         clientID: newClientID,
    //         clientSecret: clientSecret,
    //         refreshToken: refreshToken
    //     )
    //     let tokenRefreshReponseData = try JSONDecoder().decode(SuccessResponse.self, from: tokenRefreshResponse.body)

    //     XCTAssertEqual(tokenRefreshResponse.status, .ok)

    //     guard let newAccessToken = tokenRefreshReponseData.accessToken else {
    //         XCTFail()
    //         return
    //     }

    //     // Check user returned
    //     try app.test(.GET, "/user", beforeRequest: { req in
    //         req.headers.bearerAuthorization = BearerAuthorization(token: newAccessToken)
    //     }, afterResponse: { userResponse in
    //         XCTAssertEqual(userResponse.status, .ok)

    //         let user = try userResponse.content.decode(UserResponse.self)

    //         XCTAssertEqual(user.userID, userID)
    //         XCTAssertEqual(user.username, username)
    //         XCTAssertEqual(user.email, email)
    //     })
    // }

    func testAccessingProtectedRouteWithoutHeaderReturns403() throws {
        try app.test(
            .GET,
            "protected",
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .forbidden)
            }
        )
    }

    func testAccessingProtectedRouteWithoutBearerTokenReturns403() throws {
        try app.test(
            .GET,
            "protected",
            beforeRequest: { req in
                req.headers.add(name: "Authorization", value: "Something")
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .forbidden)
            }
        )
    }

    func testAccessingProtectedRouteWithoutTokenReturns403() async throws {
        try app.test(
            .GET,
            "protected",
            beforeRequest: { req in
                req.headers.add(name: "Authorization", value: "Bearer ")
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .forbidden)
            }
        )
    }

    func testAccessingProtectedRouteWithInvalidTokenReturns401() async throws {
        try app.test(
            .GET,
            "/protected/",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: "fjiojfeowoi")
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .unauthorized)
            }
        )
    }

    func testAccessingProtectedRouteWithInvalidScopeReturns401() async throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = FakeAccessToken(
            tokenString: tokenID,
            clientID: newClientID,
            userID: newUser.id,
            scopes: ["invalid"],
            expiryTime: Date().addingTimeInterval(3600)
        )
        fakeTokenManager.accessTokens[tokenID] = token

        try app.test(
            .GET,
            "/protected/",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: tokenID)
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .unauthorized)
            }
        )
    }

    func testAccessingProtectedRouteWithOneInvalidScopeOneValidReturns401() async throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = FakeAccessToken(
            tokenString: tokenID,
            clientID: newClientID,
            userID: newUser.id,
            scopes: ["invalid", scope],
            expiryTime: Date().addingTimeInterval(3600)
        )
        fakeTokenManager.accessTokens[tokenID] = token

        try app.test(
            .GET,
            "/protected/",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: tokenID)
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .unauthorized)
            }
        )
    }

    func testAccessingProtectedRouteWithLowercaseHeaderWorks() async throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = FakeAccessToken(
            tokenString: tokenID,
            clientID: newClientID,
            userID: newUser.id,
            scopes: [scope, scope2],
            expiryTime: Date().addingTimeInterval(3600)
        )
        fakeTokenManager.accessTokens[tokenID] = token

        try app.test(
            .GET,
            "/protected/",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: tokenID)
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .ok)
            }
        )
    }

    func testThatAccessingProtectedRouteWithExpiredTokenReturns401() async throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = FakeAccessToken(
            tokenString: tokenID,
            clientID: newClientID,
            userID: newUser.id,
            scopes: [scope, scope2],
            expiryTime: Date().addingTimeInterval(-3600)
        )
        fakeTokenManager.accessTokens[tokenID] = token

        try app.test(
            .GET,
            "/protected/",
            beforeRequest: { req in
                req.headers.bearerAuthorization = .init(token: tokenID)
            },
            afterResponse: { protectedResponse in
                XCTAssertEqual(protectedResponse.status, .unauthorized)
            }
        )
    }

    //    func testTokenIntrospectionEndpoint() async throws {
    //        resourceApp = Application(.testing)
    //        resourceApp.http.server.configuration.port = 8081
    //        let remoteResourceController = RemoteResourceController(client: resourceApp.client)
    //        try resourceApp.routes.register(collection: remoteResourceController)
    //
    //        let newClient = OAuthClient(clientID: newClientID, redirectURIs: [redirectURI], clientSecret: clientSecret, validScopes: [scope, scope2], confidential: true, firstParty: true, allowedGrantType: .authorization)
    //        let clientRetriever = StaticClientRetriever(clients: [newClient])
    //        let fakeUserManager = FakeUserManager()
    //        let resourceServerRetriever = FakeResourceServerRetriever()
    //        let oauthProvider = VaporOAuth.Provider(tokenManager: fakeTokenManager, clientRetriever: clientRetriever, authorizeHandler: capturingAuthouriseHandler, userManager: fakeUserManager, validScopes: [scope, scope2], resourceServerRetriever: resourceServerRetriever, authenticateUser: { $0.auth.login(self.newUser) })
    //
    //        resourceApp.middleware.use(resourceApp.sessions.middleware)
    //        resourceApp.lifecycle.use(oauthProvider)
    //        resourceApp.oAuthHelper = .remote(
    //            tokenIntrospectionEndpoint: "http://127.0.0.1:8080/oauth/token_info",
    //            client: resourceApp.client,
    //            resourceServerUsername: "testResource",
    //            resourceServerPassword: "server"
    //        )
    //
    //        do {
    //            _ = try resourceApp.testable()
    //        } catch {
    //            resourceApp.shutdown()
    //            throw error
    //        }
    //
    //        let resourceServer = OAuthResourceServer(username: "testResource", password: "server")
    //        resourceServerRetriever.resourceServers["testResource"] = resourceServer
    //
    //        try resourceApp.test(.GET, "protected") { forbiddenResponse in
    //            XCTAssertEqual(forbiddenResponse.status, .forbidden)
    //        }
    //
    //        try resourceApp.test(.GET, "protected", beforeRequest: { req in
    //            req.headers.bearerAuthorization = .init(token: "jfeiowjfeowi")
    //        }, afterResponse: { unauthorizedResponse in
    //            XCTAssertEqual(unauthorizedResponse.status, .unauthorized)
    //        })
    //
    //        let fakeTokenString = "123456789ABCDEFHGUIO"
    //        let accessToken = AccessToken(tokenString: fakeTokenString, clientID: newClientID, userID: userID, scopes: ["email", "user"], expiryTime: Date().addingTimeInterval(60))
    //        fakeTokenManager.accessTokens[fakeTokenString] = accessToken
    //        let fakeUser = OAuthUser(userID: userID, username: username, emailAddress: email, password: "leia".makeBytes())
    //        fakeUserManager.users.append(fakeUser)
    //
    //        let protectedRequest = Request(method: .get, uri: "/protected/")
    //        protectedRequest.headers[.authorization] = "Bearer \(fakeTokenString)"
    //        let protectedResponse = try resourceDrop.respond(to: protectedRequest)
    //
    //        XCTAssertEqual(protectedResponse.status, .ok)
    //
    //        let userRequest = Request(method: .get, uri: "/user")
    //        userRequest.headers[.authorization] = "Bearer \(fakeTokenString)"
    //
    //        let userResponse = try resourceDrop.respond(to: userRequest)
    //
    //        XCTAssertEqual(userResponse.status, .ok)
    //
    //        XCTAssertEqual(userResponse.json?["userID"]?.string, userID.string)
    //        XCTAssertEqual(userResponse.json?["username"]?.string, username)
    //        XCTAssertEqual(userResponse.json?["email"]?.string, email)
    //
    //        let tokenWithWrongScopeString = "jejiofjewojioe"
    //        let accessTokenWrongScopes = AccessToken(tokenString: tokenWithWrongScopeString, clientID: newClientID, userID: userID, scopes: ["wrong"], expiryTime: Date().addingTimeInterval(60))
    //        fakeTokenManager.accessTokens[tokenWithWrongScopeString] = accessTokenWrongScopes
    //
    //        let wrongScopeRequest = Request(method: .get, uri: "/protected/")
    //        wrongScopeRequest.headers[.authorization] = "Bearer \(tokenWithWrongScopeString)"
    //        let wrongScopeResponse = try resourceDrop.respond(to: wrongScopeRequest)
    //
    //        XCTAssertEqual(wrongScopeResponse.status, .unauthorized)
    //
    //        let tokenWithNoScopes = "fiewjfowe"
    //        let accessTokenWithNoScopes = AccessToken(tokenString: tokenWithNoScopes, clientID: newClientID, userID: userID, scopes: nil, expiryTime: Date().addingTimeInterval(60))
    //        fakeTokenManager.accessTokens[tokenWithNoScopes] = accessTokenWithNoScopes
    //
    //        let noScopeRequest = Request(method: .get, uri: "/protected/")
    //        noScopeRequest.headers[.authorization] = "Bearer \(tokenWithNoScopes)"
    //        let noScopeResponse = try resourceDrop.respond(to: noScopeRequest)
    //
    //        XCTAssertEqual(noScopeResponse.status, .unauthorized)
}

struct TestResourceController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let oauthMiddleware = OAuth2ScopeMiddleware(requiredScopes: ["user", "email"])
        let protected = routes.grouped(oauthMiddleware)

        protected.get("protected", use: protectedHandler)
        protected.get("user", use: getOAuthUser)
    }

    func protectedHandler(request: Request) async throws -> Response {
        Response(body: "PROTECTED")
    }

    func getOAuthUser(request: Request) async throws -> Response {
        let user = try request.auth.require(OAuthUser.self)
        let jsonResponse = UserResponse(userID: user.id, email: user.emailAddress, username: user.username)
        let response = Response()
        try response.content.encode(jsonResponse)

        return response
    }
}

struct RemoteResourceController: RouteCollection {
    let client: Client
    func boot(routes: RoutesBuilder) throws {
        let oauthMiddleware = OAuth2TokenIntrospectionMiddleware(requiredScopes: ["user", "email"])
        let protected = routes.grouped(oauthMiddleware)

        protected.get("protected", use: protectedHandler)
        protected.get("user", use: getOAuthUser)
    }

    func protectedHandler(request: Request) async throws -> Response {
        Response(body: "PROTECTED")
    }

    func getOAuthUser(request: Request) async throws -> Response {
        let user = try request.auth.require(OAuthUser.self)

        let jsonResponse = UserResponse(userID: user.id, email: user.emailAddress, username: user.username)
        let response = Response()
        try response.content.encode(jsonResponse)

        return response
    }
}

struct UserResponse: Content {
    let userID: String?
    let email: String?
    let username: String
}
