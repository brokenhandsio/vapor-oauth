import XCTVapor

@testable import VaporOAuth

class TokenIntrospectionTests: XCTestCase {
    // MARK: - Properties
    var app: Application!
    var fakeTokenManager: FakeTokenManager!
    var fakeUserManager: FakeUserManager!
    var fakeResourceServerRetriever: FakeResourceServerRetriever!
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let accessToken = "ABDEFGHIJKLMNO01234567890"
    let scope1 = "email"
    let scope2 = "create"
    let resourceServerName = "brokenhands-users"
    let resourceServerPassword = "users"
    let clientID = "some-client"

    // MARK: - Overrides

    override func setUp() {
        fakeTokenManager = FakeTokenManager()
        fakeUserManager = FakeUserManager()
        fakeResourceServerRetriever = FakeResourceServerRetriever()

        app = try! TestDataBuilder.getOAuth2Application(
            tokenManager: fakeTokenManager,
            userManager: fakeUserManager,
            validScopes: [scope1, scope2],
            resourceServerRetriever: fakeResourceServerRetriever
        )

        let resourceServer = OAuthResourceServer(username: resourceServerName, password: resourceServerPassword)
        fakeResourceServerRetriever.resourceServers[resourceServerName] = resourceServer

        let validToken = FakeAccessToken(
            tokenString: accessToken,
            clientID: clientID,
            userID: nil,
            expiryTime: Date().addingTimeInterval(60)
        )
        fakeTokenManager.accessTokens[accessToken] = validToken
    }

    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }

    // MARK: - Tests
    func testCorrectErrorWhenTokenParameterNotSuppliedInRequest() async throws {
        let response = try await getInfoResponse(token: nil)
        let responseJSON = try response.content.decode(TokenIntrospectionHandler.ErrorResponse.self)

        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON.error, "missing_token")
        XCTAssertEqual(responseJSON.errorDescription, "The token parameter is required")
    }

    func testCorrectErrorWhenNoAuthorisationSuppliied() async throws {
        let response = try await getInfoResponse(authHeader: nil)

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testCorrectErrorWhenInvalidAuthorisationSupplied() async throws {
        let response = try await getInfoResponse(authHeader: "INVALID")

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testCorrectErrorWhenInvalidUsernnameSuppliedForAuthorisation() async throws {
        let header = "UNKOWNUSER:\(resourceServerPassword)".base64String()
        let response = try await getInfoResponse(authHeader: header)

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testCorrectErrorWhenInvalidPasswordSuppliedForAuthorisation() async throws {
        let header = "\(resourceServerName):SOMEPASSWORD".base64String()
        let response = try await getInfoResponse(authHeader: header)

        XCTAssertEqual(response.status, .unauthorized)
    }

    func testThatInvalidTokenReturnsInactive() async throws {
        let response = try await getInfoResponse(token: "UNKNOWN_TOKEN")
        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertFalse(responseJSON.active)
    }

    func testThatExpiredTokenReturnsInactive() async throws {
        let tokenString = "EXPIRED_TOKEN"
        let expiredToken = FakeAccessToken(
            tokenString: tokenString,
            clientID: testClientID,
            userID: nil,
            expiryTime: Date().addingTimeInterval(-60)
        )
        fakeTokenManager.accessTokens[tokenString] = expiredToken
        let response = try await getInfoResponse(token: tokenString)

        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertFalse(responseJSON.active)
    }

    func testThatValidTokenReturnsActive() async throws {
        let response = try await getInfoResponse()

        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertTrue(responseJSON.active)
    }

    func testThatScopeReturnedInReponseIfTokenHasScope() async throws {
        let tokenString = "VALID_TOKEN"
        let validToken = FakeAccessToken(
            tokenString: tokenString,
            clientID: clientID,
            userID: nil,
            scopes: ["email", "profile"],
            expiryTime: Date().addingTimeInterval(60)
        )
        fakeTokenManager.accessTokens[tokenString] = validToken

        let response = try await getInfoResponse(token: tokenString)

        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON.active, true)
        XCTAssertEqual(responseJSON.scope, "email profile")
    }

    func testCliendIDReturnedInTokenResponse() async throws {
        let response = try await getInfoResponse()

        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON.active, true)
        XCTAssertEqual(responseJSON.clientID, clientID)
    }

    func testUsernameReturnedInTokenResponseIfTokenHasAUser() async throws {
        let userID = "123"
        let username = "hansolo"
        let tokenString = "VALID_TOKEN"
        let validToken = FakeAccessToken(
            tokenString: tokenString,
            clientID: clientID,
            userID: userID,
            expiryTime: Date().addingTimeInterval(60)
        )
        fakeTokenManager.accessTokens[tokenString] = validToken
        let newUser = OAuthUser(userID: userID, username: username, emailAddress: "han@therebelalliance.com", password: "leia")
        fakeUserManager.users.append(newUser)

        let response = try await getInfoResponse(token: tokenString)

        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON.active, true)
        XCTAssertEqual(responseJSON.username, username)
    }

    func testTokenExpiryReturnedInResponse() async throws {
        let tokenString = "VALID_TOKEN"
        let expiryDate = Date().addingTimeInterval(60)
        let validToken = FakeAccessToken(tokenString: tokenString, clientID: clientID, userID: nil, expiryTime: expiryDate)
        fakeTokenManager.accessTokens[tokenString] = validToken

        let response = try await getInfoResponse(token: tokenString)

        let responseJSON = try response.content.decode(TokenIntrospectionHandler.TokenResponse.self)

        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON.active, true)
        XCTAssertEqual(responseJSON.exp, Int(expiryDate.timeIntervalSince1970))
    }

    // MARK: - Helper method

    // Auth Header is brokenhands-users:users Base64 encoded
    func getInfoResponse(
        token: String? = "ABDEFGHIJKLMNO01234567890",
        authHeader: String? = "YnJva2VuaGFuZHMtdXNlcnM6dXNlcnM="
    ) async throws -> XCTHTTPResponse {
        // TODO - try Form URL encoded
        struct TokenData: Content {
            var token: String?
        }

        return try await withCheckedThrowingContinuation { continuation in
            do {
                try app.test(
                    .POST,
                    "/oauth/token_info",
                    beforeRequest: { request in
                        if let authHeader = authHeader {
                            request.headers.add(name: "authorization", value: "Basic \(authHeader)")
                        }
                        if let token = token {
                            let tokenData = TokenData(token: token)
                            try request.content.encode(tokenData)
                        }
                    },
                    afterResponse: { response in
                        continuation.resume(returning: response)
                    }
                )
            } catch {
                continuation.resume(throwing: error)
            }
        }
    }

}
