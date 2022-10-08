import XCTVapor
@testable import VaporOAuth

class ClientCredentialsTokenTests: XCTestCase {
    // MARK: - Properties
    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeTokenManager: FakeTokenManager!

    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let refreshToken = "ABCDEFGHIJLMNOP1234567890"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"

    // MARK: - Overrides
    override func setUp() async throws {
        fakeClientGetter = FakeClientGetter()
        fakeTokenManager = FakeTokenManager()

        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: nil,
            clientSecret: testClientSecret,
            validScopes: [scope1, scope2],
            confidential: true,
            allowedGrantType: .clientCredentials
        )

        fakeClientGetter.validClients[testClientID] = oauthClient
        fakeTokenManager.accessTokenToReturn = accessToken
        fakeTokenManager.refreshTokenToReturn = refreshToken

        app = try TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            validScopes: [scope1, scope2, scope3]
        )
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    func testCorrectErrorWhenGrantTypeNotSupplied() async throws {
        let response = try await getClientCredentialsResponse(grantType: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'grant_type' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() async throws {
        let grantType = "some_unknown_type"
        let response = try await getClientCredentialsResponse(grantType: grantType)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unsupported_grant_type")
        XCTAssertEqual(responseJSON.errorDescription, "This server does not support the '\(grantType)' grant type")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientIDNotSupplied() async throws {
        let response = try await getClientCredentialsResponse(clientID: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_id' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientIDNotValid() async throws {
        let response = try await getClientCredentialsResponse(clientID: "UNKNOWN_CLIENT")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientDoesNotAuthenticate() async throws {
        let response = try await getClientCredentialsResponse(clientSecret: "incorrectPassword")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorIfClientSecretNotSent() async throws {
        let response = try await getClientCredentialsResponse(clientSecret: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_secret' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatTokenReceivedIfClientAuthenticated() async throws {
        let response = try await getClientCredentialsResponse()

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertEqual(response.status, .ok)
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertEqual(responseJSON.refreshToken, refreshToken)
    }

    func testScopeSetOnTokenIfRequested() async throws {
        let scope = "email create"

        let response = try await getClientCredentialsResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertEqual(response.status, .ok)
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertEqual(responseJSON.refreshToken, refreshToken)
        XCTAssertEqual(responseJSON.scope, scope)

        guard let accessToken = fakeTokenManager.getAccessToken(accessToken), let refreshToken = fakeTokenManager.getRefreshToken(refreshToken) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.scopes ?? [], ["email", "create"])
        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }

    func testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo() async throws {
        let scope = "email edit"

        let response = try await getClientCredentialsResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an invalid scope")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenRequestingUnknownScope() async throws {
        let scope = "email unknown"

        let response = try await getClientCredentialsResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an unknown scope")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenNonConfidentialClientTriesToUseCredentialsGrantType() async throws {
        let newClientID = "1234"
        let newClientSecret = "1234567899"
        let newClient = OAuthClient(clientID: newClientID, redirectURIs: nil, clientSecret: newClientSecret, confidential: false, allowedGrantType: .clientCredentials)
        fakeClientGetter.validClients[newClientID] = newClient

        let response = try await getClientCredentialsResponse(clientID: newClientID, clientSecret: newClientSecret)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unauthorized_client")
        XCTAssertEqual(responseJSON.errorDescription, "You are not authorized to use the Client Credentials grant type")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testAccessTokenHasCorrectExpiryTime() async throws {
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime

        let response = try await getClientCredentialsResponse()

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

    func testClientIDSetOnAccessTokenCorrectly() async throws {
        let newClientString = "a-new-client"
        let newClient = OAuthClient(clientID: newClientString, redirectURIs: nil, clientSecret: testClientSecret, validScopes: [scope1, scope2], confidential: true, allowedGrantType: .clientCredentials)
        fakeClientGetter.validClients[newClientString] = newClient

        let response = try await getClientCredentialsResponse(clientID: newClientString)

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail()
            return
        }

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.clientID, newClientString)
    }

    func testThatRefreshTokenHasCorrectClientIDSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getClientCredentialsResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.clientID, testClientID)
    }

    func testThatRefreshTokenHasNoScopesIfNoneRequested() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getClientCredentialsResponse(scope: nil)

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertNil(refreshToken.scopes)
    }

    func testThatRefreshTokenHasCorrectScopesIfSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getClientCredentialsResponse(scope: "email create")

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }

    func testNoUserIDSetOnRefreshToken() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getClientCredentialsResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertNil(refreshToken.userID)
    }

    func testClientNotConfiguredWithAccessToClientCredentialsFlowCantAccessIt() async throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedSecret = "client-secret"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: nil, clientSecret: unauthorizedSecret, validScopes: nil, confidential: true, firstParty: true, allowedGrantType: .refresh)
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient

        let response = try await getClientCredentialsResponse(clientID: unauthorizedID, clientSecret: unauthorizedSecret)

        XCTAssertEqual(response.status, .forbidden)
    }

    func testClientConfiguredWithAccessToClientCredentialsFlowCanAccessIt() async throws {
        let authorizedID = "not-allowed"
        let authorizedSecret = "client-secret"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: nil, clientSecret: authorizedSecret, validScopes: nil, confidential: true, firstParty: true, allowedGrantType: .clientCredentials)
        fakeClientGetter.validClients[authorizedID] = authorizedClient

        let response = try await getClientCredentialsResponse(clientID: authorizedID, clientSecret: authorizedSecret)

        XCTAssertEqual(response.status, .ok)
    }

    // MARK: - Private

    func getClientCredentialsResponse(
        grantType: String? = "client_credentials",
        clientID: String? = "ABCDEF",
        clientSecret: String? = "01234567890",
        scope: String? = nil
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope
        )
    }

}
