import XCTest
import VaporOAuth
@testable import Vapor
import Sessions
import Cookies

class AuthCodeResourceServerTests: XCTestCase {
    
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testThatClientCanAccessResourceServerWithValidAuthCodeToken", testThatClientCanAccessResourceServerWithValidAuthCodeToken),
        ("testAccessingProtectedRouteWithoutHeaderReturns403", testAccessingProtectedRouteWithoutHeaderReturns403),
        ("testAccessingProtectedRouteWithoutBearerTokenReturns403", testAccessingProtectedRouteWithoutBearerTokenReturns403),
        ("testAccessingProtectedRouteWithoutTokenReturns403", testAccessingProtectedRouteWithoutTokenReturns403),
        ("testAccessingProtectedRouteWithInvalidTokenReturns401", testAccessingProtectedRouteWithInvalidTokenReturns401),
        ("testAccessingProtectedRouteWithInvalidScopeReturns401", testAccessingProtectedRouteWithInvalidScopeReturns401),
        ("testAccessingProtectedRouteWithOneInvalidScopeOneValidReturns401", testAccessingProtectedRouteWithOneInvalidScopeOneValidReturns401),
        ("testAccessingProtectedRouteWithLowercaseHeaderWorks", testAccessingProtectedRouteWithLowercaseHeaderWorks),
        ("testThatAccessingProtectedRouteWithExpiredTokenReturns401", testThatAccessingProtectedRouteWithExpiredTokenReturns401),
        ("testTokenIntrospectionEndpoint", testTokenIntrospectionEndpoint),
        ]
    
    // MARK: - Properties
    
    var drop: Droplet!
    let capturingAuthouriseHandler = CapturingAuthoriseHandler()
    let fakeTokenManager = FakeTokenManager()
    let newClientID = "the-client"
    let clientSecret = "the-secret"
    let redirectURI = "https://brokenhands.io/callback"
    let scope = "user"
    let scope2 = "email"
    let userID: Identifier = "user-id"
    let username = "han"
    let email = "han.solo@therebelalliance.com"
    var newUser: OAuthUser!
    
    // MARK: - Overrides
    
    override func setUp() {
        var config = Config([:])
        let newClient = OAuthClient(clientID: newClientID, redirectURIs: [redirectURI], clientSecret: clientSecret, validScopes: [scope, scope2], confidential: true, firstParty: true, allowedGrantType: .authorization)
        let fakeCodeManager = FakeCodeManager()
        let clientRetriever = StaticClientRetriever(clients: [newClient])
        let fakeUserManager = FakeUserManager()
        let oauthProvider = VaporOAuth.Provider(codeManager: fakeCodeManager, tokenManager: fakeTokenManager, clientRetriever: clientRetriever, authorizeHandler: capturingAuthouriseHandler, userManager: fakeUserManager, validScopes: [scope, scope2])
        
        try! config.addProvider(oauthProvider)
        config.addConfigurable(middleware: SessionsMiddleware.init, name: "sessions")
        try! config.set("droplet.middleware", ["error", "sessions"])
        
        drop = try! Droplet(config)
        
        let resourceController = TestResourceController(drop: drop)
        resourceController.addRoutes()
        
        newUser = OAuthUser(userID: userID, username: username, emailAddress: email, password: "leia".makeBytes())
        fakeUserManager.users.append(newUser)
    }
    
    // MARK: - Tests
    
    // Courtesy of https://oleb.net/blog/2017/03/keeping-xctest-in-sync/
    func testLinuxTestSuiteIncludesAllTests() {
        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
            let thisClass = type(of: self)
            let linuxCount = thisClass.allTests.count
            let darwinCount = Int(thisClass.defaultTestSuite().testCaseCount)
            XCTAssertEqual(linuxCount, darwinCount, "\(darwinCount - linuxCount) tests are missing from allTests")
        #endif
    }
    
    func testThatClientCanAccessResourceServerWithValidAuthCodeToken() throws {
        
        // Get Auth Code
        let state = "jfeiojo382497329"
        let responseType = "code"
        let response = try TestDataBuilder.getAuthRequestResponse(with: drop, responseType: responseType, clientID: newClientID, redirectURI: redirectURI, scope: "\(scope)+\(scope2)", state: state)
        
        guard let rawCookie = response.headers[.setCookie] else {
            XCTFail()
            return
        }
        
        let sessionCookie = try Cookie(bytes: rawCookie.bytes)
        
        XCTAssertEqual(capturingAuthouriseHandler.responseType, responseType)
        XCTAssertEqual(capturingAuthouriseHandler.clientID, newClientID)
        XCTAssertEqual(capturingAuthouriseHandler.redirectURI, URIParser.shared.parse(bytes: redirectURI.makeBytes()))
        XCTAssertEqual(capturingAuthouriseHandler.scope?.count, 2)
        XCTAssertTrue(capturingAuthouriseHandler.scope?.contains(scope) ?? false)
        XCTAssertTrue(capturingAuthouriseHandler.scope?.contains(scope2) ?? false)
        XCTAssertEqual(capturingAuthouriseHandler.state, state)
        XCTAssertEqual(response.status, .ok)
        
        let codeResponse = try TestDataBuilder.getAuthResponseResponse(with: drop, approve: true, clientID: newClientID, redirectURI: redirectURI, responseType: responseType, scope: "\(scope)+\(scope2)", state: state, user: newUser, csrfToken: capturingAuthouriseHandler.csrfToken, sessionCookie: sessionCookie)
        
        guard let newLocation = codeResponse.headers[.location] else {
            XCTFail()
            return
        }
        
        let codeRedirectURI = URIParser.shared.parse(bytes: newLocation.makeBytes())
                
        guard let query = codeRedirectURI.query else {
            XCTFail()
            return
        }
        
        let queryParts = query.components(separatedBy: "&")
        
        var codePart: String?
        
        for queryPart in queryParts {
            if queryPart.hasPrefix("code=") {
                let codeStartIndex = queryPart.index(queryPart.startIndex, offsetBy: 5)
                codePart = queryPart.substring(from: codeStartIndex)
            }
        }
        
        guard let codeFound = codePart else {
            XCTFail()
            return
        }
        
        print("Code was \(codeFound)")
        
        // Get Token
        
        let tokenResponse = try TestDataBuilder.getTokenRequestResponse(with: drop, grantType: "authorization_code", clientID: newClientID, clientSecret: clientSecret, redirectURI: redirectURI, code: codeFound)
        
        print("Token response was \(tokenResponse)")
        
        guard let token = tokenResponse.json?["access_token"]?.string else {
            XCTFail()
            return
        }
        
        guard let refreshToken = tokenResponse.json?["refresh_token"]?.string else {
            XCTFail()
            return
        }
        
        // Get resource
        let protectedRequest = Request(method: .get, uri: "/protected/")
        protectedRequest.headers[.authorization] = "Bearer \(token)"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .ok)
        
        // Get new token
        let tokenRefreshResponse = try TestDataBuilder.getTokenRequestResponse(with: drop, grantType: "refresh_token", clientID: newClientID, clientSecret: clientSecret, refreshToken: refreshToken)
        
        XCTAssertEqual(tokenRefreshResponse.status, .ok)
        
        guard let newAccessToken = tokenRefreshResponse.json?["access_token"]?.string else {
            XCTFail()
            return
        }
        
        // Check user returned
        let userRequest = Request(method: .get, uri: "/user")
        userRequest.headers[.authorization] = "Bearer \(newAccessToken)"
        
        let userResponse = try drop.respond(to: userRequest)
        
        XCTAssertEqual(userResponse.status, .ok)
        
        XCTAssertEqual(userResponse.json?["userID"]?.string, userID.string)
        XCTAssertEqual(userResponse.json?["username"]?.string, username)
        XCTAssertEqual(userResponse.json?["email"]?.string, email)
    }
    
    func testAccessingProtectedRouteWithoutHeaderReturns403() throws {
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .forbidden)
    }
    
    func testAccessingProtectedRouteWithoutBearerTokenReturns403() throws {
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "Something"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .forbidden)
    }
    
    func testAccessingProtectedRouteWithoutTokenReturns403() throws {
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "Bearer "
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .forbidden)
    }
    
    func testAccessingProtectedRouteWithInvalidTokenReturns401() throws {
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "Bearer fjiojfeowoi"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .unauthorized)
    }
    
    func testAccessingProtectedRouteWithInvalidScopeReturns401() throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: ["invalid"], expiryTime: Date().addingTimeInterval(3600))
        fakeTokenManager.accessTokens[tokenID] = token
        
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "Bearer \(tokenID)"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .unauthorized)
    }
    
    func testAccessingProtectedRouteWithOneInvalidScopeOneValidReturns401() throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: ["invalid", scope], expiryTime: Date().addingTimeInterval(3600))
        fakeTokenManager.accessTokens[tokenID] = token
        
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "Bearer \(tokenID)"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .unauthorized)
    }
    
    func testAccessingProtectedRouteWithLowercaseHeaderWorks() throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: [scope, scope2], expiryTime: Date().addingTimeInterval(3600))
        fakeTokenManager.accessTokens[tokenID] = token
        
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "bearer \(tokenID)"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .ok)
    }
    
    func testThatAccessingProtectedRouteWithExpiredTokenReturns401() throws {
        let tokenID = "new-token-ID-invalid-scope"
        let token = AccessToken(tokenString: tokenID, clientID: newClientID, userID: newUser.id, scopes: [scope, scope2], expiryTime: Date().addingTimeInterval(-3600))
        fakeTokenManager.accessTokens[tokenID] = token
        
        let protectedRequest = Request(method: .get, uri: "/protected/")
        
        protectedRequest.headers[.authorization] = "Bearer \(tokenID)"
        
        let protectedResponse = try drop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .unauthorized)
    }
    
    func testTokenIntrospectionEndpoint() throws {
        var resourceConfig = Config([:])
        resourceConfig.environment = .test
        try resourceConfig.set("servers.default.port", "8081")
        let resourceDrop = try Droplet(resourceConfig)
        let remoteResourceController = RemoteResourceController(drop: resourceDrop)
        remoteResourceController.addRoutes()
        
        var authConfig = try Config(arguments: ["vapor", "--env=test"])
        let newClient = OAuthClient(clientID: newClientID, redirectURIs: [redirectURI], clientSecret: clientSecret, validScopes: [scope, scope2], confidential: true, firstParty: true, allowedGrantType: .authorization)
        let clientRetriever = StaticClientRetriever(clients: [newClient])
        let fakeUserManager = FakeUserManager()
        let resourceServerRetriever = FakeResourceServerRetriever()
        let oauthProvider = VaporOAuth.Provider(tokenManager: fakeTokenManager, clientRetriever: clientRetriever, authorizeHandler: capturingAuthouriseHandler, userManager: fakeUserManager, validScopes: [scope, scope2], resourceServerRetriever: resourceServerRetriever)
        try authConfig.addProvider(oauthProvider)
        authConfig.addConfigurable(middleware: SessionsMiddleware.init, name: "sessions")
        try authConfig.set("droplet.middleware", ["error", "sessions"])
        let authDrop = try Droplet(authConfig)
        background {
            _ = try! authDrop.run()
        }
        authDrop.console.wait(seconds: 0.5)
        
        let resourceServer = OAuthResourceServer(username: "testResource", password: "server".makeBytes())
        resourceServerRetriever.resourceServers["testResource"] = resourceServer
        
        let forbiddenRequest = Request(method: .get, uri: "/protected/")
        let forbiddenResponse = try resourceDrop.respond(to: forbiddenRequest)
        
        XCTAssertEqual(forbiddenResponse.status, .forbidden)
        
        let unauthorizedRequest = Request(method: .get, uri: "/protected/")
        unauthorizedRequest.headers[.authorization] = "Bearer jfeiowjfeowi"
        let unauthorizedResponse = try resourceDrop.respond(to: unauthorizedRequest)
        
        XCTAssertEqual(unauthorizedResponse.status, .unauthorized)
        
        
        let fakeTokenString = "123456789ABCDEFHGUIO"
        let accessToken = AccessToken(tokenString: fakeTokenString, clientID: newClientID, userID: userID, scopes: ["email", "user"], expiryTime: Date().addingTimeInterval(60))
        fakeTokenManager.accessTokens[fakeTokenString] = accessToken
        let fakeUser = OAuthUser(userID: userID, username: username, emailAddress: email, password: "leia".makeBytes())
        fakeUserManager.users.append(fakeUser)
        
        let protectedRequest = Request(method: .get, uri: "/protected/")
        protectedRequest.headers[.authorization] = "Bearer \(fakeTokenString)"
        let protectedResponse = try resourceDrop.respond(to: protectedRequest)
        
        XCTAssertEqual(protectedResponse.status, .ok)
        
        let userRequest = Request(method: .get, uri: "/user")
        userRequest.headers[.authorization] = "Bearer \(fakeTokenString)"
        
        let userResponse = try resourceDrop.respond(to: userRequest)
        
        XCTAssertEqual(userResponse.status, .ok)
        
        XCTAssertEqual(userResponse.json?["userID"]?.string, userID.string)
        XCTAssertEqual(userResponse.json?["username"]?.string, username)
        XCTAssertEqual(userResponse.json?["email"]?.string, email)

    }
    
}

struct TestResourceController {
    let drop: Droplet
    
    func addRoutes() {
        
        let oauthMiddleware = OAuth2ScopeMiddleware(requiredScopes: ["user", "email"])
        let protected = drop.grouped(oauthMiddleware)
        
        protected.get("protected", handler: protectedHandler)
        protected.get("user", handler: getOAuthUser)
    }
    
    func protectedHandler(request: Request) throws -> ResponseRepresentable {
        return "PROTECTED"
    }
    
    func getOAuthUser(request: Request) throws -> ResponseRepresentable {
        let user: OAuthUser = try request.oauth.user()
        var json = JSON()
        try json.set("userID", user.id)
        try json.set("email", user.emailAddress)
        try json.set("username", user.username)
        
        return json
    }
}

struct RemoteResourceController {
    let drop: Droplet
    
    func addRoutes() {
        
        let oauthMiddleware = OAuth2TokenIntrospectionMiddleware(tokenIntrospectionEndpoint: "http://127.0.0.1:8080/oauth/token_info", requiredScopes: ["user", "email"], client: drop.client, resourceServerUsername: "testResource", resourceServerPassword: "server")
        let protected = drop.grouped(oauthMiddleware)
        
        protected.get("protected", handler: protectedHandler)
        protected.get("user", handler: getOAuthUser)
    }
    
    func protectedHandler(request: Request) throws -> ResponseRepresentable {
        return "PROTECTED"
    }
    
    func getOAuthUser(request: Request) throws -> ResponseRepresentable {
        let user: OAuthUser = try request.oauth.user()
        var json = JSON()
        try json.set("userID", user.id)
        try json.set("email", user.emailAddress)
        try json.set("username", user.username)
        
        return json
    }
}
