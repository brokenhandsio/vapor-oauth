import XCTVapor
@testable import VaporOAuth

class ImplicitGrantTests: XCTestCase {
    // MARK: - Properties
    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeTokenManager: FakeTokenManager!
    var capturingAuthHandler: CapturingAuthoriseHandler!
    var fakeSessions: FakeSessions!
    let testRedirectURIString = "https://api.brokenhands.io/callback"
    var testRedirectURI: URI!
    let testClientID = "ABCDEF"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"
    let sessionID = "the-session-ID"
    let csrfToken = "the-csrf-token"

    // MARK: - Overrides

    override func setUp() async throws {
        fakeClientGetter = FakeClientGetter()
        fakeTokenManager = FakeTokenManager()
        capturingAuthHandler = CapturingAuthoriseHandler()
        fakeSessions = FakeSessions(
            sessions: [SessionID(string: sessionID): SessionData(initialData: ["CSRFToken": csrfToken])]
        )

        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testRedirectURIString],
            validScopes: [scope1, scope2],
            allowedGrantType: .implicit
        )

        fakeClientGetter.validClients[testClientID] = oauthClient
        testRedirectURI = URI(string: testRedirectURIString)

        app = try TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            authorizeHandler: capturingAuthHandler,
            validScopes: [scope1, scope2, scope3],
            sessions: fakeSessions
        )
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    // MARK: - Request Tests
    func testCorrectErrorIfNoResponeTypeSet() async throws {

        let response = try await makeImplicitGrantRequest(responseType: nil)

        guard let redirectURL = response.headers.location?.value else {
            XCTFail()
            return
        }

        let expectedRedirectURI = "\(testRedirectURIString)?error=invalid_request&error_description=Request+was+missing+the+response_type+parameter"

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(redirectURL, expectedRedirectURI)
    }

    func testAuthHandlerSentCorrectErrorIfNoClientIDProvided() async throws {
        let response = try await makeImplicitGrantRequest(clientID: nil)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidClientID)
    }

    func testAuthHandlerSentCorrectErrorIfNoRedirectURIProvided() async throws {
        let response = try await makeImplicitGrantRequest(redirectURI: nil)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidRedirectURI)
    }

    func testAuthHandlerSentCorrectErrorIfInvalidClientIDProvided() async throws {
        let response = try await makeImplicitGrantRequest(clientID: "UNKOWN")

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidClientID)
    }

    func testAuthHandlerSentCorrectErrorIfRedirectURIDoesNotMatchClientID() async throws {
        let response = try await makeImplicitGrantRequest(redirectURI: "https://evil.com/callback")

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.authorizationError, .invalidRedirectURI)
    }

    func testAuthHandlerToldToHandleRequestIfParametersAreValid() async throws {
        let response = try await makeImplicitGrantRequest()

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(capturingAuthHandler.clientID, testClientID)
        XCTAssertEqual(capturingAuthHandler.redirectURI, testRedirectURI)
        XCTAssertEqual(capturingAuthHandler.responseType, "token")
    }

    func testStatePassedThroughToAuthorizeHandlerIfProvided() async throws {
        let state = "abcdef"
        _ = try await makeImplicitGrantRequest(state: state)

        XCTAssertEqual(capturingAuthHandler.state, state)
    }

    func testScopePassedThroughToAuthorizeHandlerIfProvided() async throws {
        _ = try await makeImplicitGrantRequest(scope: scope1)

        XCTAssertEqual(capturingAuthHandler.scope ?? [], [scope1])
    }

    func testCorrectErrorReturnedIfRequestingUnknownScope() async throws {
        let response = try await makeImplicitGrantRequest(scope: "UNKNOWN")

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
            XCTFail()
            return
        }

        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)?error=invalid_scope&error_description=scope+is+unknown")
    }

    func testCorrectErrorIfRequestingScopeClientDoesNotHaveAccessTo() async throws {
        let response = try await makeImplicitGrantRequest(scope: scope3)

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
            XCTFail()
            return
        }

        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)?error=invalid_scope&error_description=scope+is+invalid")
    }

    func testThatCSRFTokenProvidedToAuthHandler() async throws {
        _ = try await makeImplicitGrantRequest()

        XCTAssertNotNil(capturingAuthHandler.csrfToken)
    }

    func testThatSessionCookieSetWhenMakingRequest() async throws {
        let response = try await makeImplicitGrantRequest()

        XCTAssertNotNil(response.headers[.setCookie])
    }

    func testClientNotConfiguredWithAccessToImplciitFlowCantAccessItForGet() async throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .refresh)
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient

        let response = try await makeImplicitGrantRequest(clientID: unauthorizedID)

        XCTAssertEqual(response.status, .forbidden)
    }

    func testClientConfiguredWithAccessToImplicitFlowCanAccessItForGet() async throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .implicit)
        fakeClientGetter.validClients[authorizedID] = authorizedClient

        let response = try await makeImplicitGrantRequest(clientID: authorizedID)

        XCTAssertEqual(response.status, .ok)
    }

    // MARK: - Response Tests

    func testCorrectErrorReturnedIfUserDoesNotAuthorizeApplication() async throws {
        let denyResponse = try await getImplicitGrantResponse(approve: false)

        XCTAssertEqual(denyResponse.status, .seeOther)
        XCTAssertEqual(denyResponse.headers.location?.value, "\(testRedirectURIString)?error=access_denied&error_description=user+denied+the+request")
    }

    func testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication() async throws {
        let state = "xcoivjuywkdkhvusuye3kch"
        let authorizationDenyResponse = try await getImplicitGrantResponse(approve: false, state: state)

        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers.location?.value, "\(testRedirectURIString)?error=access_denied&error_description=user+denied+the+request&state=\(state)")
    }

    func testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication() async throws {
        let clientID = "ABCDEFG"
        let redirectURI = "http://new.brokenhands.io/callback"
        let client = OAuthClient(clientID: clientID, redirectURIs: [redirectURI], allowedGrantType: .implicit)
        fakeClientGetter.validClients[clientID] = client

        let authorizationDenyResponse = try await getImplicitGrantResponse(approve: false, clientID: clientID, redirectURI: redirectURI)

        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(authorizationDenyResponse.headers.location?.value, "\(redirectURI)?error=access_denied&error_description=user+denied+the+request")
    }

    func testThatAuthorizationApprovalMustBeSentInPostRequest() async throws {
        let authorizeResponse = try await getImplicitGrantResponse(approve: nil)

        XCTAssertEqual(authorizeResponse.status, .badRequest)
    }

    func testThatClientIDMustBeSentToAuthorizeApproval() async throws {
        let response = try await getImplicitGrantResponse(clientID: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectURIMustBeSentToAuthorizeApproval() async throws {
        let response = try await getImplicitGrantResponse(redirectURI: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatResponseTypeMustBeSentToAuthorizeApproval() async throws {
        let response = try await getImplicitGrantResponse(responseType: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatInvalidClientIDReturnsBadRequest() async throws {
        let response = try await getImplicitGrantResponse(clientID: "DONOTEXIST")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest() async throws {
        let response = try await getImplicitGrantResponse(redirectURI: "https://some.invalid.uri")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectURIMustBeHTTPSForProduction() async throws {
        app.shutdown()
        app = try TestDataBuilder.getOAuth2Application(
            clientRetriever: fakeClientGetter,
            authorizeHandler: capturingAuthHandler,
            environment: .production
        )

        let clientID = "ABCDE1234"
        let redirectURI = "http://api.brokenhands.io/callback"
        let newClient = OAuthClient(clientID: clientID, redirectURIs: [redirectURI], allowedGrantType: .implicit)
        fakeClientGetter.validClients[clientID] = newClient

        let response = try await getImplicitGrantResponse(clientID: clientID, redirectURI: redirectURI)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectForValidRequestContainsAccessToken() async throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try await getImplicitGrantResponse()

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
            XCTFail()
            return
        }

        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600")
    }

    func testThatRedirectContainsStateIfProvided() async throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        let state = "ashduheiufewhwe1232"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try await getImplicitGrantResponse(state: state)

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
            XCTFail()
            return
        }

        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600&state=\(state)")
    }

    func testThatTokenHasScopesIfRequested() async throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        let expectedScope = "\(scope1)+\(scope2)"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try await getImplicitGrantResponse(scope: expectedScope)

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
            XCTFail()
            return
        }

        XCTAssertEqual(redirectHeader, "\(testRedirectURIString)#token_type=bearer&access_token=\(accessToken)&expires_in=3600&scope=\(expectedScope)")
    }

    func testThatRedirectHasStateAndScopeIfBothProvided() async throws {
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        let expectedScope = "\(scope1)+\(scope2)"
        let state = "ashduheiufewhwe1232"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try await getImplicitGrantResponse(scope: expectedScope, state: state)

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
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

    func testBadRequestIfAskingForUnknownScopeForResponse() async throws {
        let response = try await getImplicitGrantResponse(scope: "UNKNOWN")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testBadRequestIfAskingForScopeClientDoesNotHaveAccessToForResponse() async throws {
        let response = try await getImplicitGrantResponse(scope: scope3)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatUserIDIsSetOnToken() async throws {
        let userID = "abcdef-123453-cbdhe"
        let accessToken = "IMPLICIT-GRANT-ACCESS-TOKEN"
        fakeTokenManager.accessTokenToReturn = accessToken
        let user = OAuthUser(userID: userID, username: "luke", emailAddress: "luke@skywalker.com", password: "obiwan")

        app.shutdown()
        app = try TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            authorizeHandler: capturingAuthHandler,
            validScopes: [scope1, scope2, scope3],
            authenticateUser: { $0.auth.login(user) },
            sessions: fakeSessions
        )

        _ = try await getImplicitGrantResponse(user: user)

        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }

        XCTAssertEqual(token.userID, userID)
    }

    func testThatNoRefreshTokenGivenForImplicitGrant() async throws {
        let response = try await getImplicitGrantResponse()

        XCTAssertEqual(response.status, .seeOther)

        guard let redirectHeader = response.headers.location?.value else {
            XCTFail()
            return
        }

        XCTAssertFalse(redirectHeader.contains("refresh_token"))
    }

    func testThatUserMustBeLoggedInWhenMakingImplicitTokenRequest() async throws {
        app.shutdown()
        app = try TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            authorizeHandler: capturingAuthHandler,
            validScopes: [scope1, scope2, scope3],
            authenticateUser: { _ in },
            sessions: fakeSessions
        )

        let response = try await getImplicitGrantResponse(user: nil)

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testCorrectExpiryTimeSetOnAccessToken() async throws {
        let accessTokenString = "some-access-token"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime

        _ = try await getImplicitGrantResponse()

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
    }

    func testCSRFTokenMustBeSubmittedWithRequest() async throws {
        let response = try await getImplicitGrantResponse(csrfToken: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRequestWithInvalidCSRFTokenFails() async throws {
        let response = try await getImplicitGrantResponse(csrfToken: "someRandomToken")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatSessionCookieMustBeSentInRequest() async throws {
        let response = try await getImplicitGrantResponse(sessionID: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatValidSessionCookieMustBeSentInRequest() async throws {
        let response = try await getImplicitGrantResponse(sessionID: "someRandomSession")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testClientNotConfiguredWithAccessToImplciitFlowCantAccessIt() async throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .refresh)
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient

        let response = try await getImplicitGrantResponse(clientID: unauthorizedID)

        XCTAssertEqual(response.status, .forbidden)
    }

    func testClientConfiguredWithAccessToImplicitFlowCanAccessIt() async throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: [testRedirectURIString], clientSecret: nil, validScopes: nil, allowedGrantType: .implicit)
        fakeClientGetter.validClients[authorizedID] = authorizedClient

        let response = try await getImplicitGrantResponse(clientID: authorizedID)

        XCTAssertEqual(response.status, .seeOther)
    }


    // MARK: - Private

    private func makeImplicitGrantRequest(
        responseType: String? = "token",
        clientID: String? = "ABCDEF",
        redirectURI: String? = "https://api.brokenhands.io/callback",
        scope: String? = nil,
        state: String? = nil
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getAuthRequestResponse(with: app, responseType: responseType, clientID: clientID, redirectURI: redirectURI, scope: scope, state: state)
    }

    private func getImplicitGrantResponse(
        approve: Bool? = true,
        clientID: String? = "ABCDEF",
        redirectURI: String? = "https://api.brokenhands.io/callback",
        responseType: String? = "token",
        scope: String? = nil,
        state: String? = nil,
        user: OAuthUser? = TestDataBuilder.anyOAuthUser(),
        csrfToken: String? = "the-csrf-token",
        sessionID: String? = "the-session-ID"
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getAuthResponseResponse(with: app, approve: approve, clientID: clientID, redirectURI: redirectURI, responseType: responseType, scope: scope, state: state, user: user, csrfToken: csrfToken, sessionID: sessionID)
    }

}
