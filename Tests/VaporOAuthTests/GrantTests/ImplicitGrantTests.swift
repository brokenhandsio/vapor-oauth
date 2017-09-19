import XCTest
import VaporOAuth
import Vapor
import Foundation
import Sessions

class ImplicitGrantTests: XCTestCase {
    
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testCorrectErrorIfNoResponeTypeSet", testCorrectErrorIfNoResponeTypeSet),
        ("testAuthHandlerSentCorrectErrorIfNoClientIDProvided", testAuthHandlerSentCorrectErrorIfNoClientIDProvided),
        ("testAuthHandlerSentCorrectErrorIfNoRedirectURIProvided", testAuthHandlerSentCorrectErrorIfNoRedirectURIProvided),
        ("testAuthHandlerSentCorrectErrorIfInvalidClientIDProvided", testAuthHandlerSentCorrectErrorIfInvalidClientIDProvided),
        ("testAuthHandlerSentCorrectErrorIfRedirectURIDoesNotMatchClientID", testAuthHandlerSentCorrectErrorIfRedirectURIDoesNotMatchClientID),
        ("testAuthHandlerToldToHandleRequestIfParametersAreValid", testAuthHandlerToldToHandleRequestIfParametersAreValid),
        ("testStatePassedThroughToAuthorizeHandlerIfProvided", testStatePassedThroughToAuthorizeHandlerIfProvided),
        ("testScopePassedThroughToAuthorizeHandlerIfProvided", testScopePassedThroughToAuthorizeHandlerIfProvided),
        ("testCorrectErrorReturnedIfRequestingUnknownScope", testCorrectErrorReturnedIfRequestingUnknownScope),
        ("testCorrectErrorIfRequestingScopeClientDoesNotHaveAccessTo", testCorrectErrorIfRequestingScopeClientDoesNotHaveAccessTo),
        ("testThatCSRFTokenProvidedToAuthHandler", testThatCSRFTokenProvidedToAuthHandler),
        ("testThatSessionCookieSetWhenMakingRequest", testThatSessionCookieSetWhenMakingRequest),
        ("testClientNotConfiguredWithAccessToImplciitFlowCantAccessItForGet", testClientNotConfiguredWithAccessToImplciitFlowCantAccessItForGet),
        ("testClientConfiguredWithAccessToImplicitFlowCanAccessItForGet", testClientConfiguredWithAccessToImplicitFlowCanAccessItForGet),
        ("testCorrectErrorReturnedIfUserDoesNotAuthorizeApplication", testCorrectErrorReturnedIfUserDoesNotAuthorizeApplication),
        ("testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication", testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication),
        ("testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication", testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication),
        ("testThatAuthorizationApprovalMustBeSentInPostRequest", testThatAuthorizationApprovalMustBeSentInPostRequest),
        ("testThatClientIDMustBeSentToAuthorizeApproval", testThatClientIDMustBeSentToAuthorizeApproval),
        ("testThatRedirectURIMustBeSentToAuthorizeApproval", testThatRedirectURIMustBeSentToAuthorizeApproval),
        ("testThatResponseTypeMustBeSentToAuthorizeApproval", testThatResponseTypeMustBeSentToAuthorizeApproval),
        ("testThatInvalidClientIDReturnsBadRequest", testThatInvalidClientIDReturnsBadRequest),
        ("testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest", testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest),
        ("testThatRedirectURIMustBeHTTPSForProduction", testThatRedirectURIMustBeHTTPSForProduction),
        ("testThatRedirectForValidRequestContainsAccessToken", testThatRedirectForValidRequestContainsAccessToken),
        ("testThatRedirectContainsStateIfProvided", testThatRedirectContainsStateIfProvided),
        ("testThatTokenHasScopesIfRequested", testThatTokenHasScopesIfRequested),
        ("testThatRedirectHasStateAndScopeIfBothProvided", testThatRedirectHasStateAndScopeIfBothProvided),
        ("testBadRequestIfAskingForUnknownScopeForResponse", testBadRequestIfAskingForUnknownScopeForResponse),
        ("testBadRequestIfAskingForScopeClientDoesNotHaveAccessToForResponse", testBadRequestIfAskingForScopeClientDoesNotHaveAccessToForResponse),
        ("testThatUserIDIsSetOnToken", testThatUserIDIsSetOnToken),
        ("testThatNoRefreshTokenGivenForImplicitGrant", testThatNoRefreshTokenGivenForImplicitGrant),
        ("testThatUserMustBeLoggedInWhenMakingImplicitTokenRequest", testThatUserMustBeLoggedInWhenMakingImplicitTokenRequest),
        ("testCorrectExpiryTimeSetOnAccessToken", testCorrectExpiryTimeSetOnAccessToken),
        ("testCSRFTokenMustBeSubmittedWithRequest", testCSRFTokenMustBeSubmittedWithRequest),
        ("testThatRequestWithInvalidCSRFTokenFails", testThatRequestWithInvalidCSRFTokenFails),
        ("testThatSessionCookieMustBeSentInRequest", testThatSessionCookieMustBeSentInRequest),
        ("testThatValidSessionCookieMustBeSentInRequest", testThatValidSessionCookieMustBeSentInRequest),
        ("testClientNotConfiguredWithAccessToImplciitFlowCantAccessIt", testClientNotConfiguredWithAccessToImplciitFlowCantAccessIt),
        ("testClientConfiguredWithAccessToImplicitFlowCanAccessIt", testClientConfiguredWithAccessToImplicitFlowCanAccessIt),
        ]
    
    // MARK: - Properties
    
    var drop: Droplet!
    let fakeClientGetter = FakeClientGetter()
    let fakeTokenManager = FakeTokenManager()
    let capturingAuthHandler = CapturingAuthoriseHandler()
    let fakeSessions = FakeSessions()
    let testRedirectURIString = "https://api.brokenhands.io/callback"
    var testRedirectURI: URI!
    let testClientID = "ABCDEF"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"
    let sessionID = "the-session-ID"
    let csrfToken = "the-csrf-token"
    
    // MARK: - Overrides
    
    override func setUp() {
        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, clientRetriever: fakeClientGetter, authorizeHandler: capturingAuthHandler, validScopes: [scope1, scope2, scope3], sessions: fakeSessions)
        let testClient = OAuthClient(clientID: testClientID, redirectURIs: [testRedirectURIString], validScopes: [scope1, scope2], allowedGrantType: .implicit)
        fakeClientGetter.validClients[testClientID] = testClient
        testRedirectURI = URIParser.shared.parse(bytes: testRedirectURIString.makeBytes())
        
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
    
    // MARK: - Request Tests
    
    func testCorrectErrorIfNoResponeTypeSet() throws {
        
        let response = try makeImplicitGrantRequest(responseType: nil)
        
        guard let redirectURL = response.headers[.location] else {
            XCTFail()
            return
        }
        
        let expectedRedirectURI = "\(testRedirectURIString)?error=invalid_request&error_description=Request+was+missing+the+response_type+parameter"
        
        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(redirectURL, expectedRedirectURI)
    }
    
    func testAuthHandlerSentCorrectErrorIfNoClientIDProvided() throws {
        let response = try makeImplicitGrantRequest(clientID: nil)
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidClientID)
    }
    
    func testAuthHandlerSentCorrectErrorIfNoRedirectURIProvided() throws {
        let response = try makeImplicitGrantRequest(redirectURI: nil)
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidRedirectURI)
    }
    
    func testAuthHandlerSentCorrectErrorIfInvalidClientIDProvided() throws {
        let response = try makeImplicitGrantRequest(clientID: "UNKOWN")
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidClientID)
    }
    
    func testAuthHandlerSentCorrectErrorIfRedirectURIDoesNotMatchClientID() throws {
        let response = try makeImplicitGrantRequest(redirectURI: "https://evil.com/callback")
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidRedirectURI)
    }
    
    func testAuthHandlerToldToHandleRequestIfParametersAreValid() throws {
        let response = try makeImplicitGrantRequest()
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.clientID, testClientID)
        XCTAssertEqual(capturingAuthHandler.redirectURI, testRedirectURI)
        XCTAssertEqual(capturingAuthHandler.responseType, "token")
    }
    
    func testStatePassedThroughToAuthorizeHandlerIfProvided() throws {
        let state = "abcdef"
        _ = try makeImplicitGrantRequest(state: state)
        
        XCTAssertEqual(capturingAuthHandler.state, state)
    }
    
    func testScopePassedThroughToAuthorizeHandlerIfProvided() throws {
        _ = try makeImplicitGrantRequest(scope: scope1)
        
        XCTAssertEqual(capturingAuthHandler.scope ?? [], [scope1])
    }
    
    func testCorrectErrorReturnedIfRequestingUnknownScope() throws {
        let response = try makeImplicitGrantRequest(scope: "UNKNOWN")
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)?error=invalid_scope&error_description=scope+is+unknown")
    }
    
    func testCorrectErrorIfRequestingScopeClientDoesNotHaveAccessTo() throws {
        let response = try makeImplicitGrantRequest(scope: scope3)
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)?error=invalid_scope&error_description=scope+is+invalid")
    }
    
    func testThatCSRFTokenProvidedToAuthHandler() throws {
        _ = try makeImplicitGrantRequest()
        
        XCTAssertNotNil(capturingAuthHandler.csrfToken)
    }
    
    func testThatSessionCookieSetWhenMakingRequest() throws {
        let response = try makeImplicitGrantRequest()
        
        XCTAssertNotNil(response.headers[.setCookie])
    }
    
    func testClientNotConfiguredWithAccessToImplciitFlowCantAccessItForGet() throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .refresh)
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient
        
        let response = try makeImplicitGrantRequest(clientID: unauthorizedID)
        
        XCTAssertEqual(response.status, .forbidden)
    }
    
    func testClientConfiguredWithAccessToImplicitFlowCanAccessItForGet() throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .implicit)
        fakeClientGetter.validClients[authorizedID] = authorizedClient
        
        let response = try makeImplicitGrantRequest(clientID: authorizedID)
        
        XCTAssertEqual(response.status, .ok)
    }
    
    // MARK: - Response Tests

    func testCorrectErrorReturnedIfUserDoesNotAuthorizeApplication() throws {
        let denyResponse = try getImplicitGrantResponse(approve: false)
        
        XCTAssertEqual(denyResponse.status, .seeOther)
        XCTAssertEqual(denyResponse.headers[.location], "\(testRedirectURIString)?error=access_denied&error_description=user+denied+the+request")
    }
    
    func testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication() throws {
        let state = "xcoivjuywkdkhvusuye3kch"
        let authorizationDenyResponse = try getImplicitGrantResponse(approve: false, state: state)
        
        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers[.location], "\(testRedirectURIString)?error=access_denied&error_description=user+denied+the+request&state=\(state)")
    }
    
    func testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication() throws {
        let clientID = "ABCDEFG"
        let redirectURI = "http://new.brokenhands.io/callback"
        let client = OAuthClient(clientID: clientID, redirectURIs: [redirectURI], allowedGrantType: .implicit)
        fakeClientGetter.validClients[clientID] = client
        
        let authorizationDenyResponse = try getImplicitGrantResponse(approve: false, clientID: clientID, redirectURI: redirectURI)
        
        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers[.location], "\(redirectURI)?error=access_denied&error_description=user+denied+the+request")
    }
    
    func testThatAuthorizationApprovalMustBeSentInPostRequest() throws {
        let authorizeResponse = try getImplicitGrantResponse(approve: nil)
        
        XCTAssertEqual(authorizeResponse.status, .badRequest)
    }
    
    func testThatClientIDMustBeSentToAuthorizeApproval() throws {
        let response = try getImplicitGrantResponse(clientID: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectURIMustBeSentToAuthorizeApproval() throws {
        let response = try getImplicitGrantResponse(redirectURI: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatResponseTypeMustBeSentToAuthorizeApproval() throws {
        let response = try getImplicitGrantResponse(responseType: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatInvalidClientIDReturnsBadRequest() throws {
        let response = try getImplicitGrantResponse(clientID: "DONOTEXIST")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest() throws {
        let response = try getImplicitGrantResponse(redirectURI: "https://some.invalid.uri")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectURIMustBeHTTPSForProduction() throws {
        drop = try! TestDataBuilder.getOAuthDroplet(clientRetriever: fakeClientGetter, authorizeHandler: capturingAuthHandler, environment: .production)
        
        let clientID = "ABCDE1234"
        let redirectURI = "http://api.brokenhands.io/callback"
        let newClient = OAuthClient(clientID: clientID, redirectURIs: [redirectURI], allowedGrantType: .implicit)
        fakeClientGetter.validClients[clientID] = newClient
        
        let response = try getImplicitGrantResponse(clientID: clientID, redirectURI: redirectURI)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRedirectForValidRequestContainsAccessToken() throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try getImplicitGrantResponse()
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600")
    }

    func testThatRedirectContainsStateIfProvided() throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        let state = "ashduheiufewhwe1232"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try getImplicitGrantResponse(state: state)
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600&state=\(state)")
    }
    
    func testThatTokenHasScopesIfRequested() throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        let expectedScope = "\(scope1)+\(scope2)"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try getImplicitGrantResponse(scope: expectedScope)
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600&scope=\(expectedScope)")
    }
    
    func testThatRedirectHasStateAndScopeIfBothProvided() throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        let expectedScope = "\(scope1)+\(scope2)"
        let state = "ashduheiufewhwe1232"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try getImplicitGrantResponse(scope: expectedScope, state: state)
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600&scope=\(expectedScope)&state=\(state)")
        
        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(token.scopes ?? [], [scope1, scope2])
        XCTAssertEqual(token.clientID, testClientID)
    }
    
    func testBadRequestIfAskingForUnknownScopeForResponse() throws {
        let response = try getImplicitGrantResponse(scope: "UNKNOWN")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testBadRequestIfAskingForScopeClientDoesNotHaveAccessToForResponse() throws {
        let response = try getImplicitGrantResponse(scope: scope3)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatUserIDIsSetOnToken() throws {
        let userID: Identifier = "abcdef-123453-cbdhe"
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        fakeTokenManager.accessTokenToReturn = accessToken
        let user = OAuthUser(userID: userID, username: "luke", emailAddress: "luke@skywalker.com", password: "obiwan".makeBytes())
        _ = try getImplicitGrantResponse(user: user)
        
        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(token.userID, userID)
    }
    
    func testThatNoRefreshTokenGivenForImplicitGrant() throws {
        let response = try getImplicitGrantResponse()
        
        XCTAssertEqual(response.status, .seeOther)
        
        guard let redirectHeader = response.headers[.location] else {
            XCTFail()
            return
        }
        
        XCTAssertFalse(redirectHeader.contains("refresh_token"))
    }
    
    func testThatUserMustBeLoggedInWhenMakingImplicitTokenRequest() throws {
        let response = try getImplicitGrantResponse(user: nil)
        
        XCTAssertEqual(response.status, .unauthorized)
    }
    
    func testCorrectExpiryTimeSetOnAccessToken() throws {
        let accessTokenString = "some-access-token"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime
        
        _ = try getImplicitGrantResponse()
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
    }
    
    func testCSRFTokenMustBeSubmittedWithRequest() throws {
        let response = try getImplicitGrantResponse(csrfToken: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatRequestWithInvalidCSRFTokenFails() throws {
        let response = try getImplicitGrantResponse(csrfToken: "someRandomToken")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatSessionCookieMustBeSentInRequest() throws {
        let response = try getImplicitGrantResponse(sessionID: nil)
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testThatValidSessionCookieMustBeSentInRequest() throws {
        let response = try getImplicitGrantResponse(sessionID: "someRandomSession")
        
        XCTAssertEqual(response.status, .badRequest)
    }
    
    func testClientNotConfiguredWithAccessToImplciitFlowCantAccessIt() throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .refresh)
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient
        
        let response = try getImplicitGrantResponse(clientID: unauthorizedID)
        
        XCTAssertEqual(response.status, .forbidden)
    }
    
    func testClientConfiguredWithAccessToImplicitFlowCanAccessIt() throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .implicit)
        fakeClientGetter.validClients[authorizedID] = authorizedClient
        
        let response = try getImplicitGrantResponse(clientID: authorizedID)
        
        XCTAssertEqual(response.status, .seeOther)
    }

    
    // MARK: - Private
    
    private func makeImplicitGrantRequest(responseType: String? = "token", clientID: String? = "ABCDEF", redirectURI: String? = "https://api.brokenhands.io/callback", scope: String? = nil, state: String? = nil) throws -> Response {
        return try TestDataBuilder.getAuthRequestResponse(with: drop, responseType: responseType, clientID: clientID, redirectURI: redirectURI, scope: scope, state: state)
    }
    
    private func getImplicitGrantResponse(approve: Bool? = true, clientID: String? = "ABCDEF", redirectURI: String? = "https://api.brokenhands.io/callback", responseType: String? = "token", scope: String? = nil, state: String? = nil, user: OAuthUser? = TestDataBuilder.anyOAuthUser(), csrfToken: String? = "the-csrf-token", sessionID: String? = "the-session-ID") throws -> Response {
        return try TestDataBuilder.getAuthResponseResponse(with: drop, approve: approve, clientID: clientID, redirectURI: redirectURI, responseType: responseType, scope: scope, state: state, user: user, csrfToken: csrfToken, sessionID: sessionID)
    }

}
