import XCTVapor
@testable import VaporOAuth

class TokenRefreshTests: XCTestCase {

    // MARK: - Properties

    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeTokenManager: FakeTokenManager!
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let refreshTokenString = "ABCDEFGJ-REFRESH-TOKEN"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"
    let scope4 = "profile"
    var validRefreshToken: RefreshToken!

    // MARK: - Overrides

    override func setUp() {
        fakeClientGetter = FakeClientGetter()
        fakeTokenManager = FakeTokenManager()

        app = try! TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter,
            validScopes: [scope1, scope2, scope3, scope4]
        )

        let testClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: nil,
            clientSecret: testClientSecret,
            validScopes: [scope1, scope2, scope4],
            confidential: true,
            allowedGrantType: .authorization
        )
        fakeClientGetter.validClients[testClientID] = testClient
        validRefreshToken = RefreshToken(
            tokenString: refreshTokenString,
            clientID: testClientID,
            userID: nil,
            scopes: [scope1, scope2]
        )
        fakeTokenManager.refreshTokens[refreshTokenString] = validRefreshToken
    }

    // MARK: - Tests
    func testCorrectErrorWhenGrantTypeNotSupplied() async throws {
        let response = try await getTokenResponse(grantType: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'grant_type' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() async throws {
        let grantType = "some_unknown_type"
        let response = try await getTokenResponse(grantType: grantType)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unsupported_grant_type")
        XCTAssertEqual(responseJSON.errorDescription, "This server does not support the '\(grantType)' grant type")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientIDNotSupplied() async throws {
        let response = try await getTokenResponse(clientID: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_id' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientIDNotValid() async throws {
        let response = try await getTokenResponse(clientID: "UNKNOWN_CLIENT")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenClientDoesNotAuthenticate() async throws {
        let response = try await getTokenResponse(clientSecret: "incorrectPassword")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorIfClientSecretNotSent() async throws {
        let response = try await getTokenResponse(clientSecret: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_secret' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrrIfRefreshTokenNotSent() async throws {
        let response = try await getTokenResponse(refreshToken: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'refresh_token' parameter")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatNonConfidentialClientsGetErrorWhenRequestingToken() async throws {
        let nonConfidentialClientID = "NONCONF"
        let nonConfidentialClientSecret = "SECRET"
        let nonConfidentialClient = OAuthClient(clientID: nonConfidentialClientID, redirectURIs: nil, clientSecret: nonConfidentialClientSecret, confidential: false, allowedGrantType: .authorization)
        fakeClientGetter.validClients[nonConfidentialClientID] = nonConfidentialClient

        let response = try await getTokenResponse(clientID: nonConfidentialClientID, clientSecret: nonConfidentialClientSecret)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unauthorized_client")
        XCTAssertEqual(responseJSON.errorDescription, "You are not authorized to use the Client Credentials grant type")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatAttemptingRefreshWithNonExistentTokenReturnsError() async throws {
        let expiredRefreshToken = "NONEXISTENTTOKEN"

        let response = try await getTokenResponse(refreshToken: expiredRefreshToken)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The refresh token is invalid")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatAttemptingRefreshWithRefreshTokenFromDifferentClientReturnsError() async throws {
        let otherClientID = "ABCDEFGHIJKLMON"
        let otherClientSecret = "1234"
        let otherClient = OAuthClient(clientID: otherClientID, redirectURIs: nil, clientSecret: otherClientSecret, confidential: true, allowedGrantType: .authorization)
        fakeClientGetter.validClients[otherClientID] = otherClient

        let response = try await getTokenResponse(clientID: otherClientID, clientSecret: otherClientSecret)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The refresh token is invalid")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatProvidingValidRefreshTokenProvidesAccessTokenInResponse() async throws {
        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessToken
        let response = try await getTokenResponse()

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertNil(responseJSON.refreshToken)
    }

    func testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo() async throws {
        let scope = "email edit"

        let response = try await getTokenResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an invalid scope")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorWhenRequestingUnknownScope() async throws {
        let scope = "email unknown"

        let response = try await getTokenResponse(scope: scope)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained an unknown scope")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testErrorIfRequestingScopeGreaterThanOriginallyRequestedEvenIfApplicatioHasAccess() async throws {
        let response = try await getTokenResponse(scope: "\(scope1) \(scope4)")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained elevated scopes")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testLoweringScopeOnRefreshSetsScopeCorrectlyOnAccessAndRefreshTokens() async throws {
        let response = try await getTokenResponse(scope: scope1)

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail()
            return
        }

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.scopes ?? [], [scope1])

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON.scope, scope1)
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.scopes ?? [], [scope1])
    }

    func testNotRequestingScopeOnRefreshDoesNotAlterOriginalScope() async throws {
        let originalScopes = validRefreshToken.scopes

        let response = try await getTokenResponse()

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let accessTokenString = responseJSON.accessToken,
              let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.scopes!, originalScopes ?? [])
        XCTAssertEqual(refreshToken.scopes!, originalScopes!)

    }

    func testRequestingTheSameScopeWhenRefreshingWorksCorrectlyAndReturnsResult() async throws {
        let scopesToRequest = validRefreshToken.scopes
        let response = try await getTokenResponse(scope: scopesToRequest?.joined(separator: " "))

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let accessTokenString = responseJSON.accessToken,
              let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.scopes!, scopesToRequest ?? [])
        XCTAssertEqual(refreshToken.scopes!, scopesToRequest!)
    }

    func testErrorWhenRequestingScopeWithNoScopesOriginallyRequestedOnRefreshToken() async throws {
        let newRefreshToken = "NEW_REFRESH_TOKEN"
        let refreshTokenWithoutScope = RefreshToken(tokenString: newRefreshToken, clientID: testClientID, userID: nil, scopes: nil)
        fakeTokenManager.refreshTokens[newRefreshToken] = refreshTokenWithoutScope

        let response = try await getTokenResponse(refreshToken: newRefreshToken, scope: scope1)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_scope")
        XCTAssertEqual(responseJSON.errorDescription, "Request contained elevated scopes")
        XCTAssertEqual(response.headers.cacheControl?.noStore, true)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testUserIDIsSetOnAccessTokenIfRefreshTokenHasOne() async throws {
        let userID = "abcdefg-123456"
        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let userIDRefreshTokenString = "ASHFUIEWHFIHEWIUF"
        let userIDRefreshToken = RefreshToken(tokenString: userIDRefreshTokenString, clientID: testClientID, userID: userID, scopes: [scope1, scope2])
        fakeTokenManager.refreshTokens[userIDRefreshTokenString] = userIDRefreshToken
        fakeTokenManager.accessTokenToReturn = accessToken
        _ = try await getTokenResponse(refreshToken: userIDRefreshTokenString)

        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }

        XCTAssertEqual(token.userID, userID)
    }

    func testClientIDSetOnAccessTokenFromRefreshToken() async throws {
        let refreshTokenString = "some-new-refreshToken"
        let clientID = "the-client-id-to-set"
        let refreshToken = RefreshToken(tokenString: refreshTokenString, clientID: clientID, userID: "some-user")
        fakeTokenManager.refreshTokens[refreshTokenString] = refreshToken
        fakeClientGetter.validClients[clientID] = OAuthClient(clientID: clientID, redirectURIs: nil, clientSecret: testClientSecret, confidential: true, allowedGrantType: .authorization)

        let response = try await getTokenResponse(clientID: clientID, refreshToken: refreshTokenString)
        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        guard let accessTokenString = responseJSON.accessToken else {
            XCTFail()
            return
        }

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.clientID, clientID)

    }

    func testExpiryTimeSetOnNewAccessToken() async throws {
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime

        let response = try await getTokenResponse()
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

    // MARK: - Private

    func getTokenResponse(
        grantType: String? = "refresh_token",
        clientID: String? = "ABCDEF",
        clientSecret: String? = "01234567890",
        refreshToken: String? = "ABCDEFGJ-REFRESH-TOKEN",
        scope: String? = nil
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            scope: scope,
            refreshToken: refreshToken
        )
    }

}
