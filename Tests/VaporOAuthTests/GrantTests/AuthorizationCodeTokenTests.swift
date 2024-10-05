import XCTVapor

@testable import VaporOAuth

class AuthorizationCodeTokenTests: XCTestCase {
    struct ErrorResponse: Decodable {
        var error: String
        var errorDescription: String

        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }

    struct SuccessResponse: Decodable {
        var tokenType: String?
        var expiresIn: Int?
        var accessToken: String?
        var refreshToken: String?
        var scope: String?

        enum CodingKeys: String, CodingKey {
            case tokenType = "token_type"
            case expiresIn = "expires_in"
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case scope
        }
    }
    // MARK: - Properties

    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeCodeManager: FakeCodeManager!
    var fakeTokenManager: FakeTokenManager!

    let testClientID = "1234567890"
    let testClientRedirectURI = "https://api.brokenhands.io/callback"
    let testClientSecret = "ABCDEFGHIJK"
    let testCodeID = "12345ABCD"
    let userID = "the-user-id"
    let scopes = ["email", "create"]

    // MARK: - Overrides

    override func setUp() async throws {
        fakeClientGetter = FakeClientGetter()
        fakeCodeManager = FakeCodeManager()
        fakeTokenManager = FakeTokenManager()

        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: [testClientRedirectURI],
            clientSecret: testClientSecret,
            allowedGrantType: .authorization
        )
        fakeClientGetter.validClients[testClientID] = oauthClient

        let testCode = OAuthCode(
            codeID: testCodeID,
            clientID: testClientID,
            redirectURI: testClientRedirectURI,
            userID: userID,
            expiryDate: Date().addingTimeInterval(60),
            scopes: scopes
        )

        fakeCodeManager.codes[testCodeID] = testCode

        app = try TestDataBuilder.getOAuth2Application(
            codeManager: fakeCodeManager,
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter
        )
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    // MARK: - Tests

    func testCorrectErrorAndHeadersReceivedWhenNoGrantTypeSent() async throws {
        let response = try await getAuthCodeResponse(grantType: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'grant_type' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() async throws {
        let grantType = "some_unknown_type"
        let response = try await getAuthCodeResponse(grantType: grantType)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "unsupported_grant_type")
        XCTAssertEqual(responseJSON.errorDescription, "This server does not support the '\(grantType)' grant type")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenNoCodeSent() async throws {
        let response = try await getAuthCodeResponse(code: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'code' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenNoRedirectURISent() async throws {
        let response = try await getAuthCodeResponse(redirectURI: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'redirect_uri' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedWhenNoClientIDSent() async throws {
        let response = try await getAuthCodeResponse(clientID: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_request")
        XCTAssertEqual(responseJSON.errorDescription, "Request was missing the 'client_id' parameter")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedIfClientIDIsUnknown() async throws {
        let response = try await getAuthCodeResponse(clientID: "UNKNOWN_CLIENT")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedIfClientSecretNotSendAndIsExpected() async throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(
            clientID: clientID,
            redirectURIs: ["https://api.brokenhands.io/callback"],
            clientSecret: "1234567890ABCD",
            allowedGrantType: .authorization
        )
        fakeClientGetter.validClients[clientID] = clientWithSecret

        let response = try await getAuthCodeResponse(clientID: clientID, clientSecret: nil)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorAndHeadersReceivedIfClientDoesNotAuthenticateCorrectly() async throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(
            clientID: clientID,
            redirectURIs: ["https://api.brokenhands.io/callback"],
            clientSecret: "1234567890ABCD",
            allowedGrantType: .authorization
        )
        fakeClientGetter.validClients[clientID] = clientWithSecret

        let response = try await getAuthCodeResponse(clientID: clientID, clientSecret: "incorrectPassword")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON.error, "invalid_client")
        XCTAssertEqual(responseJSON.errorDescription, "Request had invalid client credentials")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testErrorIfCodeDoesNotExist() async throws {
        let response = try await getAuthCodeResponse(code: "unkownCodeID")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorCodeAndHeadersReturnedIfCodeWasNotIssuedByClient() async throws {
        let codeID = "1234567"
        let code = OAuthCode(
            codeID: codeID,
            clientID: testClientID,
            redirectURI: testClientRedirectURI,
            userID: "1",
            expiryDate: Date().addingTimeInterval(60),
            scopes: nil
        )
        fakeCodeManager.codes[codeID] = code

        let clientBID = "clientB"
        let clientB = OAuthClient(clientID: clientBID, redirectURIs: [testClientRedirectURI], allowedGrantType: .authorization)
        fakeClientGetter.validClients[clientBID] = clientB

        let response = try await getAuthCodeResponse(
            code: codeID,
            redirectURI: testClientRedirectURI,
            clientID: clientBID,
            clientSecret: nil
        )

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorCodeWhenCodeIsExpired() async throws {
        let codeID = "1234567"
        let code = OAuthCode(
            codeID: codeID,
            clientID: testClientID,
            redirectURI: testClientRedirectURI,
            userID: "1",
            expiryDate: Date().addingTimeInterval(-60),
            scopes: nil
        )
        fakeCodeManager.codes[codeID] = code

        let response = try await getAuthCodeResponse(code: codeID)

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testCorrectErrorCodeWhenRedirectURIDoesNotMatchForCode() async throws {
        let response = try await getAuthCodeResponse(redirectURI: "https://different.brokenhandsio.io/callback")

        let responseJSON = try JSONDecoder().decode(ErrorResponse.self, from: response.body)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "invalid_grant")
        XCTAssertEqual(responseJSON.errorDescription, "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
    }

    func testThatCodeIsMarkedAsUsedAndCantBeReused() async throws {
        _ = try await getAuthCodeResponse(code: testCodeID)

        let secondCodeResponse = try await getAuthCodeResponse(code: testCodeID)

        XCTAssertEqual(secondCodeResponse.status, .badRequest)
        XCTAssertTrue(fakeCodeManager.usedCodes.contains(testCodeID))
    }

    func testThatCorrectResponseReceivedWhenCorrectRequestSent() async throws {
        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let refreshToken = "01234567890"

        fakeTokenManager.accessTokenToReturn = accessToken
        fakeTokenManager.refreshTokenToReturn = refreshToken

        let response = try await getAuthCodeResponse()

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertEqual(response.status, .ok)
        XCTAssertTrue(response.headers.cacheControl?.noStore ?? false)
        XCTAssertEqual(response.headers[HTTPHeaders.Name.pragma], ["no-cache"])
        XCTAssertEqual(responseJSON.tokenType, "bearer")
        XCTAssertEqual(responseJSON.expiresIn, 3600)
        XCTAssertEqual(responseJSON.accessToken, accessToken)
        XCTAssertEqual(responseJSON.refreshToken, refreshToken)
        XCTAssertEqual(responseJSON.scope, "email create")

        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }

        XCTAssertEqual(token.scopes ?? [], scopes)
    }

    func testThatNoScopeReturnedIfNoneSetOnCode() async throws {
        let newCodeString = "NEW_CODE_STRING"
        let newCode = OAuthCode(
            codeID: newCodeString,
            clientID: testClientID,
            redirectURI: testClientRedirectURI,
            userID: "1",
            expiryDate: Date().addingTimeInterval(60),
            scopes: nil
        )
        fakeCodeManager.codes[newCodeString] = newCode

        let response = try await getAuthCodeResponse(code: newCodeString)

        let responseJSON = try JSONDecoder().decode(SuccessResponse.self, from: response.body)

        XCTAssertNil(responseJSON.scope)

        guard let accessToken = fakeTokenManager.getAccessToken(responseJSON.accessToken ?? "") else {
            XCTFail()
            return
        }

        XCTAssertNil(accessToken.scopes)
    }

    func testThatClientSecretNotNeededIfClientNotIssuedWithOne() async throws {
        let clientWithoutSecret = OAuthClient(
            clientID: testClientID,
            redirectURIs: ["https://api.brokenhands.io/callback"],
            clientSecret: nil,
            allowedGrantType: .authorization
        )
        fakeClientGetter.validClients[testClientID] = clientWithoutSecret

        let response = try await getAuthCodeResponse(clientID: testClientID, clientSecret: nil)

        XCTAssertEqual(response.status, .ok)
    }

    func testThatTokenHasCorrectUserID() async throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString

        _ = try await getAuthCodeResponse()

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.userID, userID)
    }

    func testThatTokenHasCorrectClientID() async throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString

        _ = try await getAuthCodeResponse()

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.clientID, testClientID)
    }

    func testThatTokenHasCorrectScopeIfScopesSetOnCode() async throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        let newCodeString = "new-code-string"
        let scopes = ["oneScope", "aDifferentScope"]
        let newCode = OAuthCode(
            codeID: newCodeString,
            clientID: testClientID,
            redirectURI: testClientRedirectURI,
            userID: "user-id",
            expiryDate: Date().addingTimeInterval(60),
            scopes: scopes
        )
        fakeCodeManager.codes[newCodeString] = newCode

        _ = try await getAuthCodeResponse(code: newCodeString)

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.scopes ?? [], scopes)
    }

    func testTokenHasExpiryTimeSetOnIt() async throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime

        _ = try await getAuthCodeResponse()

        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
    }

    func testThatRefreshTokenHasCorrectClientIDSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getAuthCodeResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.clientID, testClientID)
    }

    func testThatRefreshTokenHasCorrectUserIDSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getAuthCodeResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.userID, userID)
    }

    func testThatRefreshTokenHasNoScopesIfNoneRequested() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        let newCodeString = "new-code"
        let newCode = OAuthCode(
            codeID: newCodeString,
            clientID: testClientID,
            redirectURI: testClientRedirectURI,
            userID: "user-ID",
            expiryDate: Date().addingTimeInterval(60),
            scopes: nil
        )
        fakeCodeManager.codes[newCodeString] = newCode

        _ = try await getAuthCodeResponse(code: newCodeString)

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertNil(refreshToken.scopes)
    }

    func testThatRefreshTokenHasCorrectScopesIfSet() async throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString

        _ = try await getAuthCodeResponse()

        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }

        XCTAssertEqual(refreshToken.scopes ?? [], scopes)
    }

    // MARK: - Private

    private func getAuthCodeResponse(
        grantType: String? = "authorization_code",
        code: String? = "12345ABCD",
        redirectURI: String? = "https://api.brokenhands.io/callback",
        clientID: String? = "1234567890",
        clientSecret: String? = "ABCDEFGHIJK"
    ) async throws -> XCTHTTPResponse {

        try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: grantType,
            clientID: clientID,
            clientSecret: clientSecret,
            redirectURI: redirectURI,
            code: code
        )
    }

}
