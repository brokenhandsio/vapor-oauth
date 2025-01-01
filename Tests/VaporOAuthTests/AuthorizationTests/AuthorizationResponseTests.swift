import XCTVapor

@testable import VaporOAuth

class AuthorizationResponseTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var fakeClientRetriever: FakeClientGetter!
    var capturingAuthoriseHandler: CapturingAuthoriseHandler!
    var fakeCodeManager: FakeCodeManager!

    static let clientID = "1234567890"
    static let redirectURI = "https://api.brokenhands.io/callback"

    //    let fakeSessions: FakeSessions!
    let scope1 = "email"
    let scope2 = "address"
    let scope3 = "profile"
    let sessionID = "the-session-ID"
    let csrfToken = "the-csrf-token"

    // MARK: - Overrides

    override func setUp() async throws {
        fakeClientRetriever = FakeClientGetter()
        capturingAuthoriseHandler = CapturingAuthoriseHandler()
        fakeCodeManager = FakeCodeManager()

        let oauthClient = OAuthClient(
            clientID: AuthorizationResponseTests.clientID,
            redirectURIs: [AuthorizationResponseTests.redirectURI],
            validScopes: [scope1, scope2],
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[AuthorizationResponseTests.clientID] = oauthClient
        let fakeSessions = FakeSessions(
            sessions: [SessionID(string: sessionID): SessionData(initialData: ["CSRFToken": csrfToken])]
        )

        app = try TestDataBuilder.getOAuth2Application(
            codeManager: fakeCodeManager,
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthoriseHandler,
            sessions: fakeSessions,
            registeredUsers: [TestDataBuilder.anyOAuthUser()]
        )
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    // MARK: - Tests

    func testThatCorrectErrorCodeReturnedIfUserDoesNotAuthorizeApplication() async throws {
        let authorizationDenyResponse = try await getAuthResponse(approve: false)

        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(
            authorizationDenyResponse.headers.location?.value,
            "\(AuthorizationResponseTests.redirectURI)?error=access_denied&error_description=user+denied+the+request"
        )
    }

    func testThatTheStateIsReturnedIfUserDoesNotAuthorizeApplication() async throws {
        let state = "xcoivjuywkdkhvusuye3kch"
        let authorizationDenyResponse = try await getAuthResponse(approve: false, state: state)

        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(
            authorizationDenyResponse.headers.location?.value,
            "\(AuthorizationResponseTests.redirectURI)?error=access_denied&error_description=user+denied+the+request&state=\(state)"
        )
    }

    func testThatRedirectURICanBeConfiguredIfUserDoesNotAuthorizeApplication() async throws {
        let clientID = "ABCDEFG"
        let redirectURI = "http://new.brokenhands.io/callback"
        let client = OAuthClient(clientID: clientID, redirectURIs: [redirectURI], allowedGrantType: .authorization)
        fakeClientRetriever.validClients[clientID] = client

        let authorizationDenyResponse = try await getAuthResponse(
            approve: false,
            clientID: clientID,
            redirectURI: redirectURI
        )

        XCTAssertEqual(authorizationDenyResponse.status, .seeOther)
        XCTAssertEqual(
            authorizationDenyResponse.headers.location?.value,
            "\(redirectURI)?error=access_denied&error_description=user+denied+the+request")
    }

    func testThatAuthorizationApprovalMustBeSentInPostRequest() async throws {
        let authorizeResponse = try await getAuthResponse(approve: nil)

        XCTAssertEqual(authorizeResponse.status, .badRequest)
    }

    func testThatClientIDMustBeSentToAuthorizeApproval() async throws {
        let response = try await getAuthResponse(clientID: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectURIMustBeSentToAuthorizeApproval() async throws {
        let response = try await getAuthResponse(redirectURI: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatResponseTypeMustBeSentToAuthorizeApproval() async throws {
        let response = try await getAuthResponse(responseType: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatInvalidClientIDReturnsBadRequest() async throws {
        let response = try await getAuthResponse(clientID: "DONOTEXIST")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectURIThatDoesNotMatchClientIDReturnsBadRequest() async throws {
        let response = try await getAuthResponse(redirectURI: "https://some.invalid.uri")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRedirectURIMustBeHTTPSForProduction() async throws {
        app.shutdown()

        app = try TestDataBuilder.getOAuth2Application(
            clientRetriever: fakeClientRetriever,
            authorizeHandler: capturingAuthoriseHandler,
            environment: .production,
            registeredUsers: [TestDataBuilder.anyOAuthUser()]
        )

        try await Task.sleep(nanoseconds: 1)  // Without this the tests are crashing (segmentation fault) on ubuntu

        let clientID = "ABCDE1234"
        let redirectURI = "http://api.brokenhands.io/callback"
        let newClient = OAuthClient(clientID: clientID, redirectURIs: [redirectURI], allowedGrantType: .authorization)
        fakeClientRetriever.validClients[clientID] = newClient

        let response = try await getAuthResponse(clientID: clientID, redirectURI: redirectURI)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatExpectedTokenReturnedForSuccessfulRequest() async throws {
        let code = "ABCDEFGHIJKL"
        fakeCodeManager.generatedCode = code

        let response = try await getAuthResponse()

        XCTAssertEqual(response.status, .seeOther)
        XCTAssertEqual(response.headers.location?.value, "\(AuthorizationResponseTests.redirectURI)?code=\(code)")
    }

    func testThatStateReturnedWithCodeIfProvidedInRequest() async throws {
        let code = "ABDDJFEIOW432423"
        let state = "grugihreiuhgbf8834dscsc"
        fakeCodeManager.generatedCode = code

        let response = try await getAuthResponse(state: state)

        XCTAssertEqual(response.headers.location?.value, "\(AuthorizationResponseTests.redirectURI)?code=\(code)&state=\(state)")
    }

    func testUserMustBeLoggedInToGetToken() async throws {
        let response = try await getAuthResponse(user: nil)

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testThatCodeHasUserIDSetOnIt() async throws {
        let codeString = "ABCDEFGHIJKL"
        fakeCodeManager.generatedCode = codeString
        let user = TestDataBuilder.anyOAuthUser()

        _ = try await getAuthResponse(user: user)

        guard let code = fakeCodeManager.getCode(codeString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(code.userID, user.id)
    }

    func testThatClientIDSetOnCode() async throws {
        _ = try await getAuthResponse()

        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }

        XCTAssertEqual(code.clientID, AuthorizationResponseTests.clientID)
    }

    func testThatScopeOnCodeIsNilIfNotSupplied() async throws {
        _ = try await getAuthResponse(scope: nil)

        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }

        XCTAssertNil(code.scopes)
    }

    func testThatCorrectScopesSetOnCodeIfSupplied() async throws {
        let scope1 = "email"
        let scope2 = "address"
        _ = try await getAuthResponse(scope: "\(scope1)+\(scope2)")

        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }

        XCTAssertEqual(code.scopes ?? [], [scope1, scope2])

    }

    func testThatRedirectURISetOnCodeCorrectly() async throws {
        _ = try await getAuthResponse()

        guard let code = fakeCodeManager.getCode(fakeCodeManager.generatedCode) else {
            XCTFail()
            return
        }

        XCTAssertEqual(code.redirectURI, AuthorizationResponseTests.redirectURI)
    }

    func testThatBadRequestReturnedForClientRequestingScopesItDoesNotHaveAccessTo() async throws {
        let response = try await getAuthResponse(scope: scope3)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatBadRequestReturnedForClientRequestingUnknownScopes() async throws {
        let response = try await getAuthResponse(scope: "some_unkown_scope")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatCSRFTokenMustBeSubmitted() async throws {
        let response = try await getAuthResponse(csrfToken: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatRequestWithInvalidCSRFTokenFails() async throws {
        let response = try await getAuthResponse(csrfToken: "someRandomToken")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatSessionCookieMustBeSentInRequest() async throws {
        let response = try await getAuthResponse(sessionID: nil)

        XCTAssertEqual(response.status, .badRequest)
    }

    func testThatValidSessionCookieMustBeSentInRequest() async throws {
        let response = try await getAuthResponse(sessionID: "someRandomSession")

        XCTAssertEqual(response.status, .badRequest)
    }

    func testClientNotConfiguredWithAccessToAuthCodeFlowCantAccessItForGet() async throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedClient = OAuthClient(
            clientID: unauthorizedID, redirectURIs: [AuthorizationResponseTests.redirectURI], clientSecret: nil, validScopes: nil,
            allowedGrantType: .implicit)
        fakeClientRetriever.validClients[unauthorizedID] = unauthorizedClient

        let response = try await getAuthResponse(clientID: unauthorizedID)

        XCTAssertEqual(response.status, .forbidden)
    }

    func testClientConfiguredWithAccessToAuthCodeFlowCanAccessItForGet() async throws {
        let authorizedID = "not-allowed"
        let authorizedClient = OAuthClient(
            clientID: authorizedID,
            redirectURIs: [AuthorizationResponseTests.redirectURI],
            clientSecret: nil,
            validScopes: nil,
            allowedGrantType: .authorization
        )
        fakeClientRetriever.validClients[authorizedID] = authorizedClient

        let response = try await getAuthResponse(clientID: authorizedID)

        XCTAssertEqual(response.status, .seeOther)
    }

    // MARK: - Private

    private func getAuthResponse(
        approve: Bool? = true,
        clientID: String? = clientID,
        redirectURI: String? = redirectURI,
        responseType: String? = "code",
        scope: String? = nil,
        state: String? = nil,
        user: OAuthUser? = TestDataBuilder.anyOAuthUser(),
        csrfToken: String? = "the-csrf-token",
        sessionID: String? = "the-session-ID"
    ) async throws -> XCTHTTPResponse {
        try await TestDataBuilder.getAuthResponseResponse(
            with: app,
            approve: approve,
            clientID: clientID,
            redirectURI: redirectURI,
            responseType: responseType,
            scope: scope,
            state: state,
            csrfToken: csrfToken,
            user: user,
            sessionID: sessionID
        )
    }
}
