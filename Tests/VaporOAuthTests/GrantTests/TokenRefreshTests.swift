//import XCTest
//import VaporOAuth
//import Vapor
//import Foundation
//
//class TokenRefreshTests: XCTestCase {
//    
//    // MARK: - All Tests
//    
//    static var allTests = [
//        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
//        ("testCorrectErrorWhenGrantTypeNotSupplied", testCorrectErrorWhenGrantTypeNotSupplied),
//        ("testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet", testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet),
//        ("testCorrectErrorWhenClientIDNotSupplied", testCorrectErrorWhenClientIDNotSupplied),
//        ("testCorrectErrorWhenClientIDNotValid", testCorrectErrorWhenClientIDNotValid),
//        ("testCorrectErrorWhenClientDoesNotAuthenticate", testCorrectErrorWhenClientDoesNotAuthenticate),
//        ("testCorrectErrorIfClientSecretNotSent", testCorrectErrorIfClientSecretNotSent),
//        ("testCorrectErrrIfRefreshTokenNotSent", testCorrectErrrIfRefreshTokenNotSent),
//        ("testThatNonConfidentialClientsGetErrorWhenRequestingToken", testThatNonConfidentialClientsGetErrorWhenRequestingToken),
//        ("testThatAttemptingRefreshWithInvalidTokenReturnsError", testThatAttemptingRefreshWithNonExistentTokenReturnsError),
//        ("testThatAttemptingRefreshWithRefreshTokenFromDifferentClientReturnsError", testThatAttemptingRefreshWithRefreshTokenFromDifferentClientReturnsError),
//        ("testThatProvidingValidRefreshTokenProvidesAccessTokenInResponse", testThatProvidingValidRefreshTokenProvidesAccessTokenInResponse),
//        ("testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo", testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo),
//        ("testCorrectErrorWhenRequestingUnknownScope", testCorrectErrorWhenRequestingUnknownScope),
//        ("testErrorIfRequestingScopeGreaterThanOriginallyRequestedEvenIfApplicatioHasAccess", testErrorIfRequestingScopeGreaterThanOriginallyRequestedEvenIfApplicatioHasAccess),
//        ("testLoweringScopeOnRefreshSetsScopeCorrectlyOnAccessAndRefreshTokens", testLoweringScopeOnRefreshSetsScopeCorrectlyOnAccessAndRefreshTokens),
//        ("testNotRequestingScopeOnRefreshDoesNotAlterOriginalScope", testNotRequestingScopeOnRefreshDoesNotAlterOriginalScope),
//        ("testRequestingTheSameScopeWhenRefreshingWorksCorrectlyAndReturnsResult", testRequestingTheSameScopeWhenRefreshingWorksCorrectlyAndReturnsResult),
//        ("testErrorWhenRequestingScopeWithNoScopesOriginallyRequestedOnRefreshToken", testErrorWhenRequestingScopeWithNoScopesOriginallyRequestedOnRefreshToken),
//        ("testUserIDIsSetOnAccessTokenIfRefreshTokenHasOne", testUserIDIsSetOnAccessTokenIfRefreshTokenHasOne),
//        ("testClientIDSetOnAccessTokenFromRefreshToken", testClientIDSetOnAccessTokenFromRefreshToken),
//        ("testExpiryTimeSetOnNewAccessToken", testExpiryTimeSetOnNewAccessToken),
//        ]
//    
//    // MARK: - Properties
//    
//    var drop: Droplet!
//    let fakeClientGetter = FakeClientGetter()
//    let fakeTokenManager = FakeTokenManager()
//    let testClientID = "ABCDEF"
//    let testClientSecret = "01234567890"
//    let refreshTokenString = "ABCDEFGJ-REFRESH-TOKEN"
//    let scope1 = "email"
//    let scope2 = "create"
//    let scope3 = "edit"
//    let scope4 = "profile"
//    var validRefreshToken: RefreshToken!
//    
//    // MARK: - Overrides
//    
//    override func setUp() {
//        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, clientRetriever: fakeClientGetter, validScopes: [scope1, scope2, scope3, scope4])
//        
//        let testClient = OAuthClient(clientID: testClientID, redirectURIs: nil, clientSecret: testClientSecret, validScopes: [scope1, scope2, scope4], confidential: true, allowedGrantType: .authorization)
//        fakeClientGetter.validClients[testClientID] = testClient
//        validRefreshToken = RefreshToken(tokenString: refreshTokenString, clientID: testClientID, userID: nil, scopes: [scope1, scope2])
//        fakeTokenManager.refreshTokens[refreshTokenString] = validRefreshToken
//    }
//    
//    // MARK: - Tests
//    
//    // Courtesy of https://oleb.net/blog/2017/03/keeping-xctest-in-sync/
//    func testLinuxTestSuiteIncludesAllTests() {
//        #if os(macOS) || os(iOS) || os(tvOS) || os(watchOS)
//            let thisClass = type(of: self)
//            let linuxCount = thisClass.allTests.count
//            let darwinCount = Int(thisClass.defaultTestSuite.testCaseCount)
//            XCTAssertEqual(linuxCount, darwinCount, "\(darwinCount - linuxCount) tests are missing from allTests")
//        #endif
//    }
//    
//    func testCorrectErrorWhenGrantTypeNotSupplied() throws {
//        let response = try getTokenResponse(grantType: nil)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
//        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'grant_type' parameter")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() throws {
//        let grantType = "some_unknown_type"
//        let response = try getTokenResponse(grantType: grantType)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "unsupported_grant_type")
//        XCTAssertEqual(responseJSON["error_description"]?.string, "This server does not support the '\(grantType)' grant type")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testCorrectErrorWhenClientIDNotSupplied() throws {
//        let response = try getTokenResponse(clientID: nil)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
//        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'client_id' parameter")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//
//    func testCorrectErrorWhenClientIDNotValid() throws {
//        let response = try getTokenResponse(clientID: "UNKNOWN_CLIENT")
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .unauthorized)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_client")
//        XCTAssertEqual(responseJSON["error_description"], "Request had invalid client credentials")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testCorrectErrorWhenClientDoesNotAuthenticate() throws {
//        let response = try getTokenResponse(clientSecret: "incorrectPassword")
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .unauthorized)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_client")
//        XCTAssertEqual(responseJSON["error_description"], "Request had invalid client credentials")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testCorrectErrorIfClientSecretNotSent() throws {
//        let response = try getTokenResponse(clientSecret: nil)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
//        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'client_secret' parameter")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testCorrectErrrIfRefreshTokenNotSent() throws {
//        let response = try getTokenResponse(refreshToken: nil)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
//        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'refresh_token' parameter")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testThatNonConfidentialClientsGetErrorWhenRequestingToken() throws {
//        let nonConfidentialClientID = "NONCONF"
//        let nonConfidentialClientSecret = "SECRET"
//        let nonConfidentialClient = OAuthClient(clientID: nonConfidentialClientID, redirectURIs: nil, clientSecret: nonConfidentialClientSecret, confidential: false, allowedGrantType: .authorization)
//        fakeClientGetter.validClients[nonConfidentialClientID] = nonConfidentialClient
//        
//        let response = try getTokenResponse(clientID: nonConfidentialClientID, clientSecret: nonConfidentialClientSecret)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "unauthorized_client")
//        XCTAssertEqual(responseJSON["error_description"], "You are not authorized to use the Client Credentials grant type")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testThatAttemptingRefreshWithNonExistentTokenReturnsError() throws {
//        let expiredRefreshToken = "NONEXISTENTTOKEN"
//        
//        let response = try getTokenResponse(refreshToken: expiredRefreshToken)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
//        XCTAssertEqual(responseJSON["error_description"], "The refresh token is invalid")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testThatAttemptingRefreshWithRefreshTokenFromDifferentClientReturnsError() throws {
//        let otherClientID = "ABCDEFGHIJKLMON"
//        let otherClientSecret = "1234"
//        let otherClient = OAuthClient(clientID: otherClientID, redirectURIs: nil, clientSecret: otherClientSecret, confidential: true, allowedGrantType: .authorization)
//        fakeClientGetter.validClients[otherClientID] = otherClient
//        
//        let response = try getTokenResponse(clientID: otherClientID, clientSecret: otherClientSecret)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
//        XCTAssertEqual(responseJSON["error_description"], "The refresh token is invalid")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testThatProvidingValidRefreshTokenProvidesAccessTokenInResponse() throws {
//        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
//        fakeTokenManager.accessTokenToReturn = accessToken
//        let response = try getTokenResponse()
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//        XCTAssertEqual(responseJSON["token_type"]?.string, "bearer")
//        XCTAssertEqual(responseJSON["expires_in"]?.int, 3600)
//        XCTAssertEqual(responseJSON["access_token"]?.string, accessToken)
//        XCTAssertNil(responseJSON["refresh_token"]?.string)
//    }
//    
//    func testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo() throws {
//        let scope = "email edit"
//
//        let response = try getTokenResponse(scope: scope)
//
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_scope")
//        XCTAssertEqual(responseJSON["error_description"]?.string, "Request contained an invalid scope")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//
//    func testCorrectErrorWhenRequestingUnknownScope() throws {
//        let scope = "email unknown"
//
//        let response = try getTokenResponse(scope: scope)
//
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_scope")
//        XCTAssertEqual(responseJSON["error_description"]?.string, "Request contained an unknown scope")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testErrorIfRequestingScopeGreaterThanOriginallyRequestedEvenIfApplicatioHasAccess() throws {
//        let response = try getTokenResponse(scope: "\(scope1) \(scope4)")
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_scope")
//        XCTAssertEqual(responseJSON["error_description"]?.string, "Request contained elevated scopes")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testLoweringScopeOnRefreshSetsScopeCorrectlyOnAccessAndRefreshTokens() throws {
//        let response = try getTokenResponse(scope: scope1)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        guard let accessTokenString = responseJSON["access_token"]?.string else {
//            XCTFail()
//            return
//        }
//        
//        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(accessToken.scopes ?? [], [scope1])
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["scope"]?.string, scope1)
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//        
//        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(refreshToken.scopes ?? [], [scope1])
//    }
//    
//    func testNotRequestingScopeOnRefreshDoesNotAlterOriginalScope() throws {
//        let originalScopes = validRefreshToken.scopes
//        
//        let response = try getTokenResponse()
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        guard let accessTokenString = responseJSON["access_token"]?.string, let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(accessToken.scopes!, originalScopes ?? [])
//        XCTAssertEqual(refreshToken.scopes!, originalScopes!)
//        
//    }
//
//    func testRequestingTheSameScopeWhenRefreshingWorksCorrectlyAndReturnsResult() throws {
//        let scopesToRequest = validRefreshToken.scopes
//        let response = try getTokenResponse(scope: scopesToRequest?.joined(separator: " "))
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        guard let accessTokenString = responseJSON["access_token"]?.string, let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(accessToken.scopes!, scopesToRequest ?? [])
//        XCTAssertEqual(refreshToken.scopes!, scopesToRequest!)
//    }
//    
//    func testErrorWhenRequestingScopeWithNoScopesOriginallyRequestedOnRefreshToken() throws {
//        let newRefreshToken = "NEW_REFRESH_TOKEN"
//        let refreshTokenWithoutScope = RefreshToken(tokenString: newRefreshToken, clientID: testClientID, userID: nil, scopes: nil)
//        fakeTokenManager.refreshTokens[newRefreshToken] = refreshTokenWithoutScope
//        
//        let response = try getTokenResponse(refreshToken: newRefreshToken, scope: scope1)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "invalid_scope")
//        XCTAssertEqual(responseJSON["error_description"]?.string, "Request contained elevated scopes")
//        XCTAssertEqual(response.headers[.cacheControl], "no-store")
//        XCTAssertEqual(response.headers[.pragma], "no-cache")
//    }
//    
//    func testUserIDIsSetOnAccessTokenIfRefreshTokenHasOne() throws {
//        let userID: Identifier = "abcdefg-123456"
//        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
//        let userIDRefreshTokenString = "ASHFUIEWHFIHEWIUF"
//        let userIDRefreshToken = RefreshToken(tokenString: userIDRefreshTokenString, clientID: testClientID, userID: userID, scopes: [scope1, scope2])
//        fakeTokenManager.refreshTokens[userIDRefreshTokenString] = userIDRefreshToken
//        fakeTokenManager.accessTokenToReturn = accessToken
//        _ = try getTokenResponse(refreshToken: userIDRefreshTokenString)
//        
//        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(token.userID, userID)
//    }
//    
//    func testClientIDSetOnAccessTokenFromRefreshToken() throws {
//        let refreshTokenString = "some-new-refreshToken"
//        let clientID = "the-client-id-to-set"
//        let refreshToken = RefreshToken(tokenString: refreshTokenString, clientID: clientID, userID: "some-user")
//        fakeTokenManager.refreshTokens[refreshTokenString] = refreshToken
//        fakeClientGetter.validClients[clientID] = OAuthClient(clientID: clientID, redirectURIs: nil, clientSecret: testClientSecret, confidential: true, allowedGrantType: .authorization)
//        
//        let response = try getTokenResponse(clientID: clientID, refreshToken: refreshTokenString)
//        
//        guard let accessTokenString = response.json?["access_token"]?.string else {
//            XCTFail()
//            return
//        }
//        
//        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(accessToken.clientID, clientID)
//        
//    }
//    
//    func testExpiryTimeSetOnNewAccessToken() throws {
//        let currentTime = Date()
//        fakeTokenManager.currentTime = currentTime
//        
//        let response = try getTokenResponse()
//        
//        guard let accessTokenString = response.json?["access_token"]?.string else {
//            XCTFail()
//            return
//        }
//        
//        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
//    }
//    
//    // MARK: - Private
//    
//    func getTokenResponse(grantType: String? = "refresh_token", clientID: String? = "ABCDEF", clientSecret: String? = "01234567890", refreshToken: String? = "ABCDEFGJ-REFRESH-TOKEN", scope: String? = nil) throws -> Response {
//        return try TestDataBuilder.getTokenRequestResponse(with: drop, grantType: grantType, clientID: clientID, clientSecret: clientSecret, scope: scope, refreshToken: refreshToken)
//    }
//
//}
