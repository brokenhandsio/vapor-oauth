import XCTVapor
@testable import VaporOAuth

class DefaultImplementationTests: XCTestCase {
    // MARK: - Tests
    func testThatEmptyResourceServerRetrieverReturnsNilWhenGettingResourceServer() async throws {
        let emptyResourceServerRetriever = EmptyResourceServerRetriever()
        
        let server = try await emptyResourceServerRetriever.getServer("some username")
        XCTAssertNil(server)
    }
    
    func testThatEmptyUserManagerReturnsNilWhenAttemptingToAuthenticate() async throws {
        let emptyUserManager = EmptyUserManager()
        let token = try await emptyUserManager.authenticateUser(username: "username", password: "password")
        XCTAssertNil(token)
    }
    
    func testThatEmptyUserManagerReturnsNilWhenTryingToGetUser() async throws {
        let emptyUserManager = EmptyUserManager()
        let id = "some-id"
        let user = try await emptyUserManager.getUser(userID: id)
        XCTAssertNil(user)
    }
    
    func testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthError() async throws {
        let emptyAuthHandler = EmptyAuthorizationHandler()
        
        let body = try await emptyAuthHandler.handleAuthorizationError(.invalidClientID).body
        
        XCTAssertEqual(body.string, "")
    }
    
    func testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthRequest() async throws {
        let emptyAuthHandler = EmptyAuthorizationHandler()
        let app = try Application.testable()
        defer { app.shutdown() }
        
        let request = Request(application: app, method: .POST, url: "/oauth/auth/", on: app.eventLoopGroup.next())
        let uri: URI = "https://api.brokenhands.io/callback"
        let authRequestObject = AuthorizationRequestObject(
            responseType: "token",
            clientID: "client-ID",
            redirectURI: uri,
            scope: ["email"],
            state: "abcdef",
            csrfToken: "01234",
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            codeChallengeMethod: "S256", nonce: nil
        )
        
        let body = try await emptyAuthHandler.handleAuthorizationRequest(
            request,
            authorizationRequestObject: authRequestObject
        ).body
        
        XCTAssertEqual(body.string, "")
    }
    
    func testThatEmptyCodeManagerReturnsNilWhenGettingCode() {
        let emptyCodeManager = EmptyCodeManager()
        XCTAssertNil(emptyCodeManager.getCode("code"))
    }
    
    func testThatEmptyCodeManagerGeneratesEmptyStringAsCode() async throws {
        let emptyCodeManager = EmptyCodeManager()
        let id: String = "identifier"
        
        // Await the result of the asynchronous call
        let generatedCode = try await emptyCodeManager.generateCode(
            userID: id,
            clientID: "client-id",
            redirectURI: "https://api.brokenhands.io/callback",
            scopes: nil,
            codeChallenge: "dummyChallenge",
            codeChallengeMethod: "S256"
        )
        
        // Perform the assertion
        XCTAssertEqual(generatedCode, "")
    }
    
    func testThatCodeUsedDoesNothingInEmptyCodeManager() {
        let emptyCodeManager = EmptyCodeManager()
        let id = "identifier"
        let code = OAuthCode(
            codeID: "id",
            clientID: "client-id",
            redirectURI: "https://api.brokenhands.io/callback",
            userID: id,
            expiryDate: Date(),
            scopes: nil,
            codeChallenge: "dummyChallenge",
            codeChallengeMethod: "S256"
        )
        emptyCodeManager.codeUsed(code)
    }
}
