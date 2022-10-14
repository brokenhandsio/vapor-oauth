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

        let oauthProvider = Provider(
            codeManager: fakeCodeManager,
            tokenManager: fakeTokenManager,
            clientRetriever: clientRetriever,
            authorizeHandler: capturingAuthouriseHandler,
            userManager: fakeUserManager,
            validScopes: [scope, scope2],
            authenticateUser: { req in req.auth.login(self.newUser) }
        )

        app = Application(.testing)

        app.middleware.use(app.sessions.middleware)
        app.lifecycle.use(oauthProvider)

        let resourceController = TestResourceController()
        try app.routes
            .grouped(AuthorizePostMiddleware(authenticateUser: { $0.auth.login(self.newUser) }))
            .register(collection: resourceController)

        do {
            _ = try app.testable()
        } catch {
            app.shutdown()
            throw error
        }
    }

    // MARK: - Tests
    func testThatClientCanAccessResourceServerWithValidAuthCodeToken() async throws {

        // Get Auth Code
        let state = "jfeiojo382497329"
        let responseType = "code"
        let response = try await TestDataBuilder.getAuthRequestResponse(
            with: app,
            responseType: responseType,
            clientID: newClientID,
            redirectURI: redirectURI,
            scope: "\(scope)+\(scope2)",
            state: state
        )

        guard let cookie = response.headers.setCookie else {
            XCTFail()
            return
        }

        XCTAssertEqual(capturingAuthouriseHandler.responseType, responseType)
        XCTAssertEqual(capturingAuthouriseHandler.clientID, newClientID)
        XCTAssertEqual(capturingAuthouriseHandler.redirectURI, "\(redirectURI)")
        XCTAssertEqual(capturingAuthouriseHandler.scope?.count, 2)
        XCTAssertTrue(capturingAuthouriseHandler.scope?.contains(scope) ?? false)
        XCTAssertTrue(capturingAuthouriseHandler.scope?.contains(scope2) ?? false)
        XCTAssertEqual(capturingAuthouriseHandler.state, state)
        XCTAssertEqual(response.status, .ok)

        let codeResponse = try await TestDataBuilder.getAuthResponseResponse(
            with: app,
            approve: true,
            clientID: newClientID,
            redirectURI: redirectURI,
            responseType: responseType,
            scope: "\(scope)+\(scope2)",
            state: state,
            user: newUser,
            csrfToken: capturingAuthouriseHandler.csrfToken,
            sessionCookie: cookie
        )

        guard let newLocation = codeResponse.headers.location?.value else {
            XCTFail("Expected location header in response.")
            return
        }

        let codeRedirectURI = URI(string: newLocation)

        guard let query = codeRedirectURI.query else {
            XCTFail()
            return
        }

        let queryParts = query.components(separatedBy: "&")

        var codePart: String?

        for queryPart in queryParts {
            if queryPart.hasPrefix("code=") {
                let codeStartIndex = queryPart.index(queryPart.startIndex, offsetBy: 5)
                codePart = String(queryPart[codeStartIndex...])
            }
        }

        guard let codeFound = codePart else {
            XCTFail()
            return
        }

        print("Code was \(codeFound)")

        // Get Token

        let tokenResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "authorization_code",
            clientID: newClientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI,
            code: codeFound
        )

        let tokenReponseData = try JSONDecoder().decode(SuccessResponse.self, from: tokenResponse.body)

        print("Token response was \(tokenResponse)")

        guard let token = tokenReponseData.accessToken else {
            XCTFail()
            return
        }

        guard let refreshToken = tokenReponseData.refreshToken else {
            XCTFail()
            return
        }

        // Get resource
        try app.test(.GET, "/protected", beforeRequest: { req in
            req.headers.bearerAuthorization = BearerAuthorization(token: token)
        }, afterResponse: { protectedResponse in
            XCTAssertEqual(protectedResponse.status, .ok)
        })

        // Get new token
        let tokenRefreshResponse = try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: "refresh_token",
            clientID: newClientID,
            clientSecret: clientSecret,
            refreshToken: refreshToken
        )
        let tokenRefreshReponseData = try JSONDecoder().decode(SuccessResponse.self, from: tokenRefreshResponse.body)

        XCTAssertEqual(tokenRefreshResponse.status, .ok)

        guard let newAccessToken = tokenRefreshReponseData.accessToken else {
            XCTFail()
            return
        }

        // Check user returned
        try app.test(.GET, "/user", beforeRequest: { req in
            req.headers.bearerAuthorization = BearerAuthorization(token: newAccessToken)
        }, afterResponse: { userResponse in
            XCTAssertEqual(userResponse.status, .ok)

            let user = try userResponse.content.decode(UserResponse.self)

            XCTAssertEqual(user.userID, userID)
            XCTAssertEqual(user.username, username)
            XCTAssertEqual(user.email, email)
        })
    }

//    func testAccessingProtectedRouteWithoutHeaderReturns403() async throws {
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .forbidden)
//    }
//
//    func testAccessingProtectedRouteWithoutBearerTokenReturns403() async throws {
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "Something"
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .forbidden)
//    }
//
//    func testAccessingProtectedRouteWithoutTokenReturns403() async throws {
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "Bearer "
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .forbidden)
//    }
//
//    func testAccessingProtectedRouteWithInvalidTokenReturns401() async throws {
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "Bearer fjiojfeowoi"
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .unauthorized)
//    }
//
//    func testAccessingProtectedRouteWithInvalidScopeReturns401() async throws {
//        let tokenID = "new-token-ID-invalid-scope"
//        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: ["invalid"], expiryTime: Date().addingTimeInterval(3600))
//        fakeTokenManager.accessTokens[tokenID] = token
//
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "Bearer \(tokenID)"
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .unauthorized)
//    }
//
//    func testAccessingProtectedRouteWithOneInvalidScopeOneValidReturns401() async throws {
//        let tokenID = "new-token-ID-invalid-scope"
//        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: ["invalid", scope], expiryTime: Date().addingTimeInterval(3600))
//        fakeTokenManager.accessTokens[tokenID] = token
//
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "Bearer \(tokenID)"
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .unauthorized)
//    }
//
//    func testAccessingProtectedRouteWithLowercaseHeaderWorks() async throws {
//        let tokenID = "new-token-ID-invalid-scope"
//        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: [scope, scope2], expiryTime: Date().addingTimeInterval(3600))
//        fakeTokenManager.accessTokens[tokenID] = token
//
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "bearer \(tokenID)"
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .ok)
//    }
//
//    func testThatAccessingProtectedRouteWithExpiredTokenReturns401() async throws {
//        let tokenID = "new-token-ID-invalid-scope"
//        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: [scope, scope2], expiryTime: Date().addingTimeInterval(-3600))
//        fakeTokenManager.accessTokens[tokenID] = token
//
//        let protectedRequest = Request(method: .get, uri: "/protected/")
//
//        protectedRequest.headers[.authorization] = "Bearer \(tokenID)"
//
//        let protectedResponse = try drop.respond(to: protectedRequest)
//
//        XCTAssertEqual(protectedResponse.status, .unauthorized)
//    }
//
//    func testTokenIntrospectionEndpoint() async throws {
//        var resourceConfig = Config([:])
//        resourceConfig.environment = .test
//        try resourceConfig.set("servers.default.port", "8081")
//        let resourceDrop = try Droplet(resourceConfig)
//        let remoteResourceController = RemoteResourceController(drop: resourceDrop)
//        remoteResourceController.addRoutes()
//
//        var authConfig = try Config(arguments: ["vapor", "--env=test"])
//        let newClient = OAuthClient(clientID: newClientID, redirectURIs: [redirectURI], clientSecret: clientSecret, validScopes: [scope, scope2], confidential: true, firstParty: true, allowedGrantType: .authorization)
//        let clientRetriever = StaticClientRetriever(clients: [newClient])
//        let fakeUserManager = FakeUserManager()
//        let resourceServerRetriever = FakeResourceServerRetriever()
//        let oauthProvider = VaporOAuth.Provider(tokenManager: fakeTokenManager, clientRetriever: clientRetriever, authorizeHandler: capturingAuthouriseHandler, userManager: fakeUserManager, validScopes: [scope, scope2], resourceServerRetriever: resourceServerRetriever)
//        try authConfig.addProvider(oauthProvider)
//        authConfig.addConfigurable(middleware: SessionsMiddleware.init, name: "sessions")
//        try authConfig.set("droplet.middleware", ["error", "sessions"])
//        let authDrop = try Droplet(authConfig)
//        background {
//            _ = try! authDrop.run()
//        }
//        authDrop.console.wait(seconds: 0.5)
//
//        let resourceServer = OAuthResourceServer(username: "testResource", password: "server".makeBytes())
//        resourceServerRetriever.resourceServers["testResource"] = resourceServer
//
//        let forbiddenRequest = Request(method: .get, uri: "/protected/")
//        let forbiddenResponse = try resourceDrop.respond(to: forbiddenRequest)
//
//        XCTAssertEqual(forbiddenResponse.status, .forbidden)
//
//        let unauthorizedRequest = Request(method: .get, uri: "/protected/")
//        unauthorizedRequest.headers[.authorization] = "Bearer jfeiowjfeowi"
//        let unauthorizedResponse = try resourceDrop.respond(to: unauthorizedRequest)
//
//        XCTAssertEqual(unauthorizedResponse.status, .unauthorized)
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
//    }
//
//    func testErrorThrownIfTryingToInitialiseFromConfig() async throws {
//        var errorThrown = false
//        var errorDescription: String?
//        let config = Config([:])
//        do {
//            try config.addProvider(VaporOAuth.Provider.self)
//        } catch let error as OAuthProviderError {
//            errorThrown = true
//            errorDescription = error.description
//        }
//
//        XCTAssertTrue(errorThrown)
//        XCTAssertEqual("The OAuth Provider cannot be created with a Config and must be created manually", errorDescription)
//    }

}

struct TestResourceController: RouteCollection {
    func boot(routes: RoutesBuilder) throws {
        let oauthMiddleware = OAuth2ScopeMiddleware(requiredScopes: ["user", "email"])
        let protected = routes.grouped(oauthMiddleware)

        protected.get("protected", use: protectedHandler)
        protected.get("user", use: getOAuthUser)
    }

    func protectedHandler(request: Request) async throws -> Response {
        return Response(body: "PROTECTED")
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
        let oauthMiddleware = OAuth2TokenIntrospectionMiddleware(
            tokenIntrospectionEndpoint: "http://127.0.0.1:8080/oauth/token_info",
            requiredScopes: ["user", "email"],
            client: client,
            resourceServerUsername: "testResource",
            resourceServerPassword: "server"
        )
        let protected = routes.grouped(oauthMiddleware)

        protected.get("protected", use: protectedHandler)
        protected.get("user", use: getOAuthUser)
    }

    func protectedHandler(request: Request) async throws -> Response {
        return Response(body: "PROTECTED")
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
