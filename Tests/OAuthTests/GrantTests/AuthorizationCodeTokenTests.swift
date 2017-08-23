import XCTest
import OAuth
import Vapor
import Foundation

class AuthorizationCodeTokenTests: XCTestCase {
    
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testThatResponseTypeMustBeSentInAuthCodeRequest", testCorrectErrorAndHeadersReceivedWhenNoGrantTypeSent),
        ("testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet", testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet),
        ("testCorrectErrorAndHeadersReceivedWhenNoCodeSent", testCorrectErrorAndHeadersReceivedWhenNoCodeSent),
        ("testCorrectErrorAndHeadersReceivedWhenNoRedirectURISent", testCorrectErrorAndHeadersReceivedWhenNoRedirectURISent),
        ("testCorrectErrorAndHeadersReceivedWhenNoClientIDSent", testCorrectErrorAndHeadersReceivedWhenNoClientIDSent),
        ("testCorrectErrorAndHeadersReceivedIfClientSecretNotSendAndIsExpected", testCorrectErrorAndHeadersReceivedIfClientSecretNotSendAndIsExpected),
        ("testCorrectErrorAndHeadersReceivedIfClientIDIsUnknown", testCorrectErrorAndHeadersReceivedIfClientIDIsUnknown),
        ("testCorrectErrorAndHeadersReceivedIfClientDoesNotAuthenticateCorrectly", testCorrectErrorAndHeadersReceivedIfClientDoesNotAuthenticateCorrectly),
        ("testErrorIfCodeDoesNotExist", testErrorIfCodeDoesNotExist),
        ("testCorrectErrorCodeAndHeadersReturnedIfCodeWasNotIssuedByClient", testCorrectErrorCodeAndHeadersReturnedIfCodeWasNotIssuedByClient),
        ("testCorrectErrorCodeWhenCodeIsExpired", testCorrectErrorCodeWhenCodeIsExpired),
        ("testCorrectErrorCodeWhenRedirectURIDoesNotMatchForCode", testCorrectErrorCodeWhenRedirectURIDoesNotMatchForCode),
        ("testThatCodeCantBeReused", testThatCodeIsMarkedAsUsedAndCantBeReused),
        ("testThatCorrectResponseReceivedWhenCorrectRequestSent", testThatCorrectResponseReceivedWhenCorrectRequestSent),
        ("testThatClientSecretNotNeededIfClientNotIssuedWithOne", testThatClientSecretNotNeededIfClientNotIssuedWithOne),
        ("testThatNoScopeReturnedIfNoneSetOnCode", testThatNoScopeReturnedIfNoneSetOnCode),
        ("testThatTokenHasCorrectUserID", testThatTokenHasCorrectUserID),
        ("testThatTokenHasCorrectClientID", testThatTokenHasCorrectClientID),
        ("testThatTokenHasCorrectScopeIfScopesSetOnCode", testThatTokenHasCorrectScopeIfScopesSetOnCode),
        ("testTokenHasExpiryTimeSetOnIt", testTokenHasExpiryTimeSetOnIt),
        ("testThatRefreshTokenHasCorrectClientIDSet", testThatRefreshTokenHasCorrectClientIDSet),
        ("testThatRefreshTokenHasCorrectUserIDSet", testThatRefreshTokenHasCorrectUserIDSet),
        ("testThatRefreshTokenHasNoScopesIfNoneRequested", testThatRefreshTokenHasNoScopesIfNoneRequested),
        ("testThatRefreshTokenHasCorrectScopesIfSet", testThatRefreshTokenHasCorrectScopesIfSet),
    ]
    
    // MARK: - Properties
    
    var drop: Droplet!
    let fakeClientGetter = FakeClientGetter()
    let fakeCodeManager = FakeCodeManager()
    let fakeTokenManager = FakeTokenManager()
    let testClientID = "1234567890"
    let testClientSecret = "ABCDEFGHIJK"
    let testClientRedirectURI = "https://api.brokenhands.io/callback"
    let testCodeID = "12345ABCD"
    let userID: Identifier = "the-user-id"
    let scopes = ["email", "create"]
    
    // MARK: - Overrides
    
    override func setUp() {
        drop = try! TestDataBuilder.getOAuthDroplet(codeManager: fakeCodeManager, tokenManager: fakeTokenManager, clientRetriever: fakeClientGetter)
        
        let testClient = OAuthClient(clientID: testClientID, redirectURIs: [testClientRedirectURI], clientSecret: testClientSecret, allowedGrantType: .authorization)
        fakeClientGetter.validClients[testClientID] = testClient
        let testCode = OAuthCode(codeID: testCodeID, clientID: testClientID, redirectURI: testClientRedirectURI, userID: userID, expiryDate: Date().addingTimeInterval(60), scopes: scopes)
        fakeCodeManager.codes[testCodeID] = testCode
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
    
    func testCorrectErrorAndHeadersReceivedWhenNoGrantTypeSent() throws {
        let response = try getAuthCodeResponse(grantType: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'grant_type' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() throws {
        let grantType = "some_unknown_type"
        let response = try getAuthCodeResponse(grantType: grantType)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "unsupported_grant_type")
        XCTAssertEqual(responseJSON["error_description"]?.string, "This server does not support the '\(grantType)' grant type")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedWhenNoCodeSent() throws {
        let response = try getAuthCodeResponse(code: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'code' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedWhenNoRedirectURISent() throws {
        let response = try getAuthCodeResponse(redirectURI: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'redirect_uri' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedWhenNoClientIDSent() throws {
        let response = try getAuthCodeResponse(clientID: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'client_id' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedIfClientIDIsUnknown() throws {
        let response = try getAuthCodeResponse(clientID: "UNKNOWN_CLIENT")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_client")
        XCTAssertEqual(responseJSON["error_description"], "Request had invalid client credentials")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedIfClientSecretNotSendAndIsExpected() throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(clientID: clientID, redirectURIs: ["https://api.brokenhands.io/callback"], clientSecret: "1234567890ABCD", allowedGrantType: .authorization)
        fakeClientGetter.validClients[clientID] = clientWithSecret
        
        let response = try getAuthCodeResponse(clientID: clientID, clientSecret: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_client")
        XCTAssertEqual(responseJSON["error_description"], "Request had invalid client credentials")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorAndHeadersReceivedIfClientDoesNotAuthenticateCorrectly() throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(clientID: clientID, redirectURIs: ["https://api.brokenhands.io/callback"], clientSecret: "1234567890ABCD", allowedGrantType: .authorization)
        fakeClientGetter.validClients[clientID] = clientWithSecret
        
        let response = try getAuthCodeResponse(clientID: clientID, clientSecret: "incorrectPassword")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .unauthorized)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_client")
        XCTAssertEqual(responseJSON["error_description"], "Request had invalid client credentials")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testErrorIfCodeDoesNotExist() throws {
        let response = try getAuthCodeResponse(code: "unkownCodeID")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
        XCTAssertEqual(responseJSON["error_description"], "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorCodeAndHeadersReturnedIfCodeWasNotIssuedByClient() throws {
        let codeID = "1234567"
        let code = OAuthCode(codeID: codeID, clientID: testClientID, redirectURI: testClientRedirectURI, userID: "1", expiryDate: Date().addingTimeInterval(60), scopes: nil)
        fakeCodeManager.codes[codeID] = code
        
        let clientBID = "clientB"
        let clientB = OAuthClient(clientID: clientBID, redirectURIs: [testClientRedirectURI], allowedGrantType: .authorization)
        fakeClientGetter.validClients[clientBID] = clientB
        
        let response = try getAuthCodeResponse(code: codeID, redirectURI: testClientRedirectURI, clientID: clientBID, clientSecret: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
        XCTAssertEqual(responseJSON["error_description"], "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorCodeWhenCodeIsExpired() throws {
        let codeID = "1234567"
        let code = OAuthCode(codeID: codeID, clientID: testClientID, redirectURI: testClientRedirectURI, userID: "1", expiryDate: Date().addingTimeInterval(-60), scopes: nil)
        fakeCodeManager.codes[codeID] = code
        
        let response = try getAuthCodeResponse(code: codeID)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
        XCTAssertEqual(responseJSON["error_description"], "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorCodeWhenRedirectURIDoesNotMatchForCode() throws {
        let response = try getAuthCodeResponse(redirectURI: "https://different.brokenhandsio.io/callback")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
        XCTAssertEqual(responseJSON["error_description"], "The code provided was invalid or expired, or the redirect URI did not match")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testThatCodeIsMarkedAsUsedAndCantBeReused() throws {
        _ = try getAuthCodeResponse(code: testCodeID)
        
        let secondCodeResponse = try getAuthCodeResponse(code: testCodeID)
        
        XCTAssertEqual(secondCodeResponse.status, .badRequest)
        XCTAssertTrue(fakeCodeManager.usedCodes.contains(testCodeID))
    }
    
    func testThatCorrectResponseReceivedWhenCorrectRequestSent() throws {
        let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        let refreshToken = "01234567890"
        
        fakeTokenManager.accessTokenToReturn = accessToken
        fakeTokenManager.refreshTokenToReturn = refreshToken
        
        let response = try getAuthCodeResponse()
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
        XCTAssertEqual(responseJSON["token_type"]?.string, "bearer")
        XCTAssertEqual(responseJSON["expires_in"]?.int, 3600)
        XCTAssertEqual(responseJSON["access_token"]?.string, accessToken)
        XCTAssertEqual(responseJSON["refresh_token"]?.string, refreshToken)
        XCTAssertEqual(responseJSON["scope"]?.string, "email create")
        
        guard let token = fakeTokenManager.getAccessToken(accessToken) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(token.scopes ?? [], scopes)
    }
    
    func testThatNoScopeReturnedIfNoneSetOnCode() throws {
        let newCodeString = "NEW_CODE_STRING"
        let newCode = OAuthCode(codeID: newCodeString, clientID: testClientID, redirectURI: testClientRedirectURI, userID: "1", expiryDate: Date().addingTimeInterval(60), scopes: nil)
        fakeCodeManager.codes[newCodeString] = newCode
        
        let response = try getAuthCodeResponse(code: newCodeString)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertNil(responseJSON["scope"]?.string)
        
        guard let accessToken = fakeTokenManager.getAccessToken(responseJSON["access_token"]?.string ?? "") else {
            XCTFail()
            return
        }
        
        XCTAssertNil(accessToken.scopes)
    }
    
    func testThatClientSecretNotNeededIfClientNotIssuedWithOne() throws {
        let clientWithoutSecret = OAuthClient(clientID: testClientID, redirectURIs: ["https://api.brokenhands.io/callback"], clientSecret: nil, allowedGrantType: .authorization)
        fakeClientGetter.validClients[testClientID] = clientWithoutSecret
        
        let response = try getAuthCodeResponse(clientID: testClientID, clientSecret: nil)
        
        XCTAssertEqual(response.status, .ok)
    }
    
    func testThatTokenHasCorrectUserID() throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        
        _ = try getAuthCodeResponse()
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.userID, userID)
    }
    
    func testThatTokenHasCorrectClientID() throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        
        _ = try getAuthCodeResponse()
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.clientID, testClientID)
    }
    
    func testThatTokenHasCorrectScopeIfScopesSetOnCode() throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        let newCodeString = "new-code-string"
        let scopes = ["oneScope", "aDifferentScope"]
        let newCode = OAuthCode(codeID: newCodeString, clientID: testClientID, redirectURI: testClientRedirectURI, userID: "user-id", expiryDate: Date().addingTimeInterval(60), scopes: scopes)
        fakeCodeManager.codes[newCodeString] = newCode
        
        _ = try getAuthCodeResponse(code: newCodeString)
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.scopes ?? [], scopes)
    }
    
    func testTokenHasExpiryTimeSetOnIt() throws {
        let accessTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.accessTokenToReturn = accessTokenString
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime
        
        _ = try getAuthCodeResponse()
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
    }
    
    func testThatRefreshTokenHasCorrectClientIDSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getAuthCodeResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.clientID, testClientID)
    }
    
    func testThatRefreshTokenHasCorrectUserIDSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getAuthCodeResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.userID, userID)
    }
    
    func testThatRefreshTokenHasNoScopesIfNoneRequested() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        let newCodeString = "new-code"
        let newCode = OAuthCode(codeID: newCodeString, clientID: testClientID, redirectURI: testClientRedirectURI, userID: "user-ID", expiryDate: Date().addingTimeInterval(60), scopes: nil)
        fakeCodeManager.codes[newCodeString] = newCode
        
        _ = try getAuthCodeResponse(code: newCodeString)
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertNil(refreshToken.scopes)
    }
    
    func testThatRefreshTokenHasCorrectScopesIfSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getAuthCodeResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.scopes ?? [], scopes)
    }
    
    // MARK: - Private
    
    private func getAuthCodeResponse(grantType: String? = "authorization_code", code: String? = "12345ABCD", redirectURI: String? = "https://api.brokenhands.io/callback", clientID: String? = "1234567890", clientSecret: String? = "ABCDEFGHIJK") throws -> Response {
        
        return try TestDataBuilder.getTokenRequestResponse(with: drop, grantType: grantType, clientID: clientID, clientSecret: clientSecret, redirectURI: redirectURI, code: code)
    }

}
