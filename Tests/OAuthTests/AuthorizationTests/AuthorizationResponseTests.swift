import XCTest
import OAuth
import Vapor
import Sessions

class AuthorizationResponseTests: XCTestCase {
    
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testThatCorrectErrorCodeReturnedIfUserDoesNotAuthorizeApplication", testThatCorrectErrorCodeReturnedIfUserDoesNotAuthorizeApplication),
        ("testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication", testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication),
        ("testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication", testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication),
        ("testThatAuthorizationApprovalMustBeSentInPostRequest", testThatAuthorizationApprovalMustBeSentInPostRequest),
        ("testThatClientIDMustBeSentToAuthorizeApproval", testThatClientIDMustBeSentToAuthorizeApproval),
        ("testThatRedirectURIMustBeSentToAuthorizeApproval", testThatRedirectURIMustBeSentToAuthorizeApproval),
        ("testThatResponseTypeMustBeSentToAuthorizeApproval", testThatResponseTypeMustBeSentToAuthorizeApproval),
        ("testThatInvalidClientIDReturnsBadRequest", testThatInvalidClientIDReturnsBadRequest),
        ("testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest", testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest),
        ("testThatRedirectURIMustBeHTTPSForProduction", testThatRedirectURIMustBeHTTPSForProduction),
        ("testThatExpectedTokenReturnedForSuccessfulRequest", testThatExpectedTokenReturnedForSuccessfulRequest),
        ("testThatStateReturnedWithCodeIfProvidedInRequest", testThatStateReturnedWithCodeIfProvidedInRequest),
        ("testUserMustBeLoggedInToGetToken", testUserMustBeLoggedInToGetToken),
        ("testThatCodeHasUserIDSetOnIt", testThatCodeHasUserIDSetOnIt),
        ("testThatClientIDSetOnCode", testThatClientIDSetOnCode),
        ("testThatScopeOnCodeIsNilIfNotSupplied", testThatScopeOnCodeIsNilIfNotSupplied),
        ("testThatCorrectScopesSetOnCodeIfSupplied", testThatCorrectScopesSetOnCodeIfSupplied),
        ("testThatRedirectURISetOnCodeCorrectly", testThatRedirectURISetOnCodeCorrectly),
        ("testThatBadRequestReturnedForClientRequestingScopesItDoesNotHaveAccessTo", testThatBadRequestReturnedForClientRequestingScopesItDoesNotHaveAccessTo),
        ("testThatBadRequestReturnedForClientRequestingUnknownScopes", testThatBadRequestReturnedForClientRequestingUnknownScopes),
        ("testThatCSRFTokenMustBeSubmitted", testThatCSRFTokenMustBeSubmitted),
        ("testThatRequestWithInvalidCSRFTokenFails", testThatRequestWithInvalidCSRFTokenFails),
        ("testThatSessionCookieMustBeSentInRequest", testThatSessionCookieMustBeSentInRequest),
        ("testThatValidSessionCookieMustBeSentInRequest", testThatValidSessionCookieMustBeSentInRequest),
        ("testClientNotConfiguredWithAccessToAuthCodeFlowCantAccessItForGet", testClientNotConfiguredWithAccessToAuthCodeFlowCantAccessItForGet),
        ("testClientConfiguredWithAccessToAuthCodeFlowCanAccessItForGet", testClientConfiguredWithAccessToAuthCodeFlowCanAccessItForGet),
    ]
    
    
    // MARK: - Properties
    
    var drop: Droplet!
    let fakeClientRetriever = FakeClientGetter()
    let capturingAuthoriseHandler = CapturingAuthoriseHandler()
    let fakeCodeManager = FakeCodeManager()
    let fakeSessions = FakeSessions()
    static let clientID = "1234567890"
    static let redirectURI = "https://api.brokenhands.io/callback"
    static let userID = "abdfeg-321313"
    let scope1 = "email"
    let scope2 = "address"
    let scope3 = "profile"
    let sessionID = "the-session-ID"
    let csrfToken = "the-csrf-token"
    
    // MARK: - Overrides
    
    override func setUp() {
        let oauthClient = OAuthClient(clientID: AuthorizationResponseTests.clientID, redirectURIs: [AuthorizationResponseTests.redirectURI], validScopes: [scope1, scope2])
        fakeClientRetriever.validClients[AuthorizationResponseTests.clientID] = oauthClient
        drop = try! TestDataBuilder.getOAuthDroplet(codeManager: fakeCodeManager, clientRetriever: fakeClientRetriever, authorizeHandler: capturingAuthoriseHandler, validScopes: [scope1, scope2, scope3], sessions: fakeSessions)
        let currentSession = Session(identifier: sessionID)
        currentSession.data["CSRFToken"] = csrfToken.makeNode(in: nil)
        fakeSessions.sessions[sessionID] = currentSession
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
    
    func testThatCorrectErrorCodeReturnedIfUserDoesNotAuthorizeApplication() throws {
        let authorizationDenyResponse = try getAuthResponse(approve: false)
        
        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers[.location], "\(AuthorizationResponseTests.redirectURI)?error=access_denied&error_description=user+denied+the+request")
    }
    
    func testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication() throws {
        let state = "xcoivjuywkdkhvusuye3kch"
        let authorizationDenyResponse = try getAuthResponse(approve: false, state: state)
        
        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers[.location], "\(AuthorizationResponseTests.redirectURI)?error=access_denied&error_description=user+denied+the+request&state=\(state)")
    }
    
    func testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication() throws {
        let clientID = "ABCDEFG"
        let redirectURI = "http://new.brokenhands.io/callback"
        let client = OAuthClient(clientID: clientID, redirectURIs: [redirectURI])
        fakeClientRetriever.validClients[clientID] = client
        
        let authorizationDenyResponse = try getAuthResponse(approve: false, clientID: clientID, redirectURI: redirectURI)
        
        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers[.location], "\(redirectURI)?error=access_denied&error_description=user+denied+the+request")
    }
    
    func testThatAuthorizationApprovalMustBeSentInPostRequest() throws {
        let authorizeResponse = try getAuthResponse(approve: nil)
        
        XCTAssertEqual(authorizeResponse.status, .badRequest)
    }
    
    func testThatClientIDMustBeSentToAuthorizeApproval() throws {
        let response = try getAuthResponse(clientID: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectURIMustBeSentToAuthorizeApproval() throws {
        let response = try getAuthResponse(redirectURI: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatResponseTypeMustBeSentToAuthorizeApproval() throws {
        let response = try getAuthResponse(responseType: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatInvalidClientIDReturnsBadRequest() throws {
        let response = try getAuthResponse(clientID: "DONOTEXIST")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest() throws {
        let response = try getAuthResponse(redirectURI: "https://some.invalid.uri")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectURIMustBeHTTPSForProduction() throws {
        drop = try! TestDataBuilder.getOAuthDroplet(clientRetriever: fakeClientRetriever, authorizeHandler: capturingAuthoriseHandler, environment: .production)
        
        let clientID = "ABCDE1234"
        let redirectURI = "http://api.brokenhands.io/callback"
        let newClient = OAuthClient(clientID: clientID, redirectURIs: [redirectURI])
        fakeClientRetriever.validClients[clientID] = newClient
        
        let response = try getAuthResponse(clientID: clientID, redirectURI: redirectURI)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatExpectedTokenReturnedForSuccessfulRequest() throws {
        let code = "ABCDEFGHIJKL"
        fakeCodeManager.generatedCode = code
        
        let response = try getAuthResponse()
        
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(response.headers[.location], "\(AuthorizationResponseTests.redirectURI)?code=\(code)")
    }
    
    func testThatStateReturnedWithCodeIfProvidedInRequest() throws {
        let code = "ABDDJFEIOW432423"
        let state = "grugihreiuhgbf8834dscsc"
        fakeCodeManager.generatedCode = code
        
        let response = try getAuthResponse(state: state)
        
        XCTAssertEqual(response.headers[.location], "\(AuthorizationResponseTests.redirectURI)?code=\(code)&state=\(state)")
    }
    
    func testUserMustBeLoggedInToGetToken() throws {
        let response = try getAuthResponse(user: nil)
        
        XCTAssertEqual(response.status, .unauthorized)
    }
    
    func testThatCodeHasUserIDSetOnIt() throws {
        let codeString = "ABCDEFGHIJKL"
        fakeCodeManager.generatedCode = codeString
        let user = TestDataBuilder.anyOAuthUser()
        
        _ = try getAuthResponse(user: user)
        
        guard let code = fakeCodeManager.getCode(codeString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(code.userID, user.id)
    }
    
    func testThatClientIDSetOnCode() throws {
        _ = try getAuthResponse()
        
        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(code.clientID, AuthorizationResponseTests.clientID)
    }
    
    func testThatScopeOnCodeIsNilIfNotSupplied() throws {
        _ = try getAuthResponse(scope: nil)
        
        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }
        
        XCTAssertNil(code.scopes)
    }
    
    func testThatCorrectScopesSetOnCodeIfSupplied() throws {
        let scope1 = "email"
        let scope2 = "address"
        _ = try getAuthResponse(scope: "\(scope1)+\(scope2)")
        
        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(code.scopes ?? [], [scope1, scope2])

    }
    
    func testThatRedirectURISetOnCodeCorrectly() throws {
        _ = try getAuthResponse()
        
        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(code.redirectURI, AuthorizationResponseTests.redirectURI)
    }
    
    func testThatBadRequestReturnedForClientRequestingScopesItDoesNotHaveAccessTo() throws {
        let response = try getAuthResponse(scope: scope3)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatBadRequestReturnedForClientRequestingUnknownScopes() throws {
        let response = try getAuthResponse(scope: "some_unkown_scope")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatCSRFTokenMustBeSubmitted() throws {
        let response = try getAuthResponse(csrfToken: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRequestWithInvalidCSRFTokenFails() throws {
        let response = try getAuthResponse(csrfToken: "someRandomToken")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatSessionCookieMustBeSentInRequest() throws {
        let response = try getAuthResponse(sessionID: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatValidSessionCookieMustBeSentInRequest() throws {
        let response = try getAuthResponse(sessionID: "someRandomSession")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testClientNotConfiguredWithAccessToAuthCodeFlowCantAccessItForGet() throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: [AuthorizationResponseTests.redirectURI], clientSecret: nil, validScopes: nil, allowedGrantTypes: [.implicit, .password, .clientCredentials, .refresh])
        fakeClientRetriever.validClients[unauthorizedID] = unauthorizedClient
        
        let response = try getAuthResponse(clientID: unauthorizedID)
        
        XCTAssertEqual(response.status, .forbidden)
    }
    
    func testClientConfiguredWithAccessToAuthCodeFlowCanAccessItForGet() throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: [AuthorizationResponseTests.redirectURI], clientSecret: nil, validScopes: nil, allowedGrantTypes: [.authorization])
        fakeClientRetriever.validClients[authorizedID] = authorizedClient
        
        let response = try getAuthResponse(clientID: authorizedID)
        
        XCTAssertEqual(response.status, .seeOther)
    }
        
    // MARK: - Private
    
    private func getAuthResponse(approve: Bool? = true, clientID: String? = clientID, redirectURI: String? = redirectURI, responseType: String? = "code", scope: String? = nil, state: String? = nil, user: OAuthUser? = TestDataBuilder.anyOAuthUser(), csrfToken: String? = "the-csrf-token", sessionID: String? = "the-session-ID") throws -> Response {
        
        return try TestDataBuilder.getAuthResponseResponse(with: drop, approve: approve, clientID: clientID, redirectURI: redirectURI, responseType: responseType, scope: scope, state: state, user: user, csrfToken: csrfToken, sessionID: sessionID)
    }
}
