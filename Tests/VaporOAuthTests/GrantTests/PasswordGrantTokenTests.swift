import XCTVapor

@testable import VaporOAuth

class PasswordGrantTokenTests: XCTestCase {
    // MARK: - Properties
    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeUserManager: FakeUserManager!
    var fakeTokenManager: FakeTokenManager!
    var capturingLogger: CapturingLogger!
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let testUsername = "testUser"
    let testPassword = "testPassword"
    let testUserID = "ABCD-FJUH-31232"
    let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let refreshToken = "ABCDEFGHIJLMNOP1234567890"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"

    // MARK: - Overrides
    override class func setUp() {
        super.setUp()
        LoggingSystem.bootstrap { _ in
            CapturingLogger.shared
        }
    }

    override func setUp() {
        fakeClientGetter = FakeClientGetter()
        fakeUserManager = FakeUserManager()
        fakeTokenManager = FakeTokenManager()
        capturingLogger = .shared

        app = try! TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            userManager: fakeUserManager,
            validScopes: [scope1, scope2, scope3],
            logger: capturingLogger
        )

        let testClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: nil,
            clientSecret: testClientSecret,
            validScopes: [scope1, scope2],
            firstParty: true,
            allowedGrantType: .password
        )

        fakeClientGetter.validClients[testClientID] = testClient
        let testUser = OAuthUser(userID: testUserID, username: testUsername, emailAddress: nil, password: testPassword)
        fakeUserManager.users.append(testUser)
        fakeTokenManager.accessTokenToReturn = accessToken
        fakeTokenManager.refreshTokenToReturn = refreshToken
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    // MARK: - Tests

    func testCorrectErrorWhenGrantTypeNotSupplied() async throws {
        let response = try await getPasswordResponse(grantType: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'grant_type' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() async throws {
        let grantType = "some_unknown_type"
        let response = try await getPasswordResponse(grantType: grantType)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unsupported_grant_type")
        XCTAssertEqual(responseJSON.errorDescription, "This server does not support the '\(grantType)' grant type")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenUsernameNotSupplied() async throws {
        let response = try await getPasswordResponse(username: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'username' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenPasswordNotSupplied() async throws {
        let response = try await getPasswordResponse(password: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'password' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientIDNotSupplied() async throws {
        let response = try await getPasswordResponse(clientID: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_id' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientIDNotValid() async throws {
        let response = try await getPasswordResponse(clientID: "UNKNOWN_CLIENT")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientDoesNotAuthenticate() async throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(
            clientID: clientID,
            redirectURIs: ["https://api.brokenhands.io/callback"],
            clientSecret: "1234567890ABCD",
            allowedGrantType: .password
        )
        fakeClientGetter.validClients[clientID] = clientWithSecret

        let response = try await getPasswordResponse(clientID: clientID, clientSecret: "incorrectPassword")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorIfClientSecretNotSentAndIsExpected() async throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(
            clientID: clientID,
            redirectURIs: ["https://api.brokenhands.io/callback"],
            clientSecret: "1234567890ABCD",
            allowedGrantType: .password
        )
        fakeClientGetter.validClients[clientID] = clientWithSecret

        let response = try await getPasswordResponse(clientID: clientID, clientSecret: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenUserDoesNotExist() async throws {
        let response = try await getPasswordResponse(username: "UNKNOWN_USER")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenPasswordIsIncorrect() async throws {
        let response = try await getPasswordResponse(password: "INCORRECT_PASSWORD")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatTokenReceivedIfUserAuthenticated() async throws {
        let response = try await getPasswordResponse()

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertEqual(responseJSON.refreshToken, refreshToken)
    }

    func testScopeSetOnTokenIfRequested() async throws {
        let scope = "email create"

        let response = try await getPasswordResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertEqual(responseJSON.refreshToken, refreshToken)
        XCTAssertEqual(responseJSON.scope, scope)

        guard let accessToken = fakeTokenManager.getAccessToken(accessToken),
            let refreshToken = fakeTokenManager.getRefreshToken(refreshToken)
        else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.scopes ?? [], ["email", "create"])
        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }

    func testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo() async throws {
        let scope = "email edit"

        let response = try await getPasswordResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an invalid scope")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenRequestingUnknownScope() async throws {
        let scope = "email unknown"

        let response = try await getPasswordResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an unknown scope")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhen3rdParyClientTriesToUsePassword() async throws {
        let newClientID = "AB1234"
        let newClient = OAuthClient(clientID: newClientID, redirectURIs: nil, firstParty: false, allowedGrantType: .password)
        fakeClientGetter.validClients[newClientID] = newClient

        let response = try await getPasswordResponse(clientID: newClientID, clientSecret: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unauthorized_client")
        XCTAssertEqual(responseJSON.errorDescription, "Password Credentials grant is not allowed")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testMessageLoggedForIncorrectLogin() async throws {
        _ = try await getPasswordResponse(password: "INCORRECT_PASSWORD")

        XCTAssertEqual(capturingLogger.logLevel, .warning)
        XCTAssertEqual(capturingLogger.logMessage, "LOGIN WARNING: Invalid login attempt for user \(testUsername)")
    }

    func testUserIsAssociatedWithTokenID() async throws {
        let response = try await getPasswordResponse()

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let token = fakeTokenManager.getAccessToken(responseJSON.accessToken ?? "") else {
            XCTFail()
            return
        }

        XCTAssertEqual(token.userID, testUserID)
    }

    func testExpiryTimeIsSetOnAccessToken() async throws {
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime

        let response = try await getPasswordResponse()
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail()
            return
        }

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
    }

    func testThatRefreshTokenHasCorrectClientIDSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getPasswordResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.clientID, testClientID)
    }

    func testThatRefreshTokenHasNoScopesIfNoneRequested() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getPasswordResponse(scope: nil)

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertNil(refreshToken.scopes)
    }

    func testThatRefreshTokenHasCorrectScopesIfSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getPasswordResponse(scope: "email create")

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }

    func testUserIDSetOnRefreshToken() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getPasswordResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.userID, testUserID)
    }

    func testClientNotConfiguredWithAccessToPasswordFlowCantAccessIt() async throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedSecret = "client-secret"
        let unauthorizedClient = OAuthClient(
            clientID: unauthorizedID,
            redirectURIs: nil,
            clientSecret: unauthorizedSecret,
            validScopes: nil,
            confidential: true,
            firstParty: true,
            allowedGrantType: .clientCredentials
        )
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient

        let response = try await getPasswordResponse(clientID: unauthorizedID, clientSecret: unauthorizedSecret)

        XCTAssertEqual(response.status, .forbidden)
    }

    func testClientConfiguredWithAccessToPasswordFlowCanAccessIt() async throws {
        let authorizedID = "not-allowed"
        let authorizedSecret = "client-secret"
        let authorizedClient = OAuthClient(
            clientID: authorizedID,
            redirectURIs: nil,
            clientSecret: authorizedSecret,
            validScopes: nil,
            confidential: true,
            firstParty: true,
            allowedGrantType: .password
        )
        fakeClientGetter.validClients[authorizedID] = authorizedClient

        let response = try await getPasswordResponse(clientID: authorizedID, clientSecret: authorizedSecret)

        XCTAssertEqual(response.status, .ok)
    }

    // MARK: - Private

    func getPasswordResponse(
        grantType: String? = "password",
        username: String? = "testUser",
        password: String? = "testPassword",
        clientID: String? = "ABCDEF",
        clientSecret: String? = "01234567890",
        scope: String? = nil
    ) async throws -> XCTHTTPResponse {
        try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope,
            username: username,
            password: password
        )
    }

}
