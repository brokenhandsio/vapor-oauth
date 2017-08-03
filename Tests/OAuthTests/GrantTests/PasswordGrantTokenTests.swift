import XCTest
import OAuth
import Vapor
import Foundation

class PasswordGrantTokenTests: XCTestCase {
    
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testCorrectErrorWhenGrantTypeNotSupplied", testCorrectErrorWhenGrantTypeNotSupplied),
        ("testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet", testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet),
        ("testCorrectErrorWhenUsernameNotSupplied", testCorrectErrorWhenUsernameNotSupplied),
        ("testCorrectErrorWhenPasswordNotSupplied", testCorrectErrorWhenPasswordNotSupplied),
        ("testCorrectErrorWhenClientIDNotSupplied", testCorrectErrorWhenClientIDNotSupplied),
        ("testCorrectErrorWhenClientIDNotValid", testCorrectErrorWhenClientIDNotValid),
        ("testCorrectErrorWhenClientDoesNotAuthenticate", testCorrectErrorWhenClientDoesNotAuthenticate),
        ("testCorrectErrorIfClientSecretNotSentAndIsExpected", testCorrectErrorIfClientSecretNotSentAndIsExpected),
        ("testCorrectErrorWhenUserDoesNotExist", testCorrectErrorWhenUserDoesNotExist),
        ("testCorrectErrorWhenPasswordIsIncorrect", testCorrectErrorWhenPasswordIsIncorrect),
        ("testThatTokenReceivedIfUserAuthenticated", testThatTokenReceivedIfUserAuthenticated),
        ("testScopeSetOnTokenIfRequested", testScopeSetOnTokenIfRequested),
        ("testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo", testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo),
        ("testCorrectErrorWhenRequestingUnknownScope", testCorrectErrorWhenRequestingUnknownScope),
        ("testCorrectErrorWhen3rdParyClientTriesToUsePassword", testCorrectErrorWhen3rdParyClientTriesToUsePassword),
        ("testMessageLoggedForIncorrectLogin", testMessageLoggedForIncorrectLogin),
        ("testUserIsAssociatedWithTokenID", testUserIsAssociatedWithTokenID),
        ("testExpiryTimeIsSetOnAccessToken", testExpiryTimeIsSetOnAccessToken),
        ("testThatRefreshTokenHasCorrectClientIDSet", testThatRefreshTokenHasCorrectClientIDSet),
        ("testThatRefreshTokenHasNoScopesIfNoneRequested", testThatRefreshTokenHasNoScopesIfNoneRequested),
        ("testThatRefreshTokenHasCorrectScopesIfSet", testThatRefreshTokenHasCorrectScopesIfSet),
        ("testUserIDSetOnRefreshToken", testUserIDSetOnRefreshToken),
        ("testClientNotConfiguredWithAccessToPasswordFlowCantAccessIt", testClientNotConfiguredWithAccessToPasswordFlowCantAccessIt),
        ("testClientConfiguredWithAccessToPasswordFlowCanAccessIt", testClientConfiguredWithAccessToPasswordFlowCanAccessIt),
        ]
    
    // MARK: - Properties
    
    var drop: Droplet!
    let fakeClientGetter = FakeClientGetter()
    let fakeUserManager = FakeUserManager()
    let fakeTokenManager = FakeTokenManager()
    let capturingLogger = CapturingLogger()
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let testUsername = "testUser"
    let testPassword = "testPassword"
    let testUserID: Identifier = "ABCD-FJUH-31232"
    let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let refreshToken = "ABCDEFGHIJLMNOP1234567890"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"
    
    // MARK: - Overrides
    
    override func setUp() {
        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, clientRetriever: fakeClientGetter, userManager: fakeUserManager, validScopes: [scope1, scope2, scope3], log: capturingLogger)
        
        let testClient = OAuthClient(clientID: testClientID, redirectURIs: nil, clientSecret: testClientSecret, validScopes: [scope1, scope2], firstParty: true)
        fakeClientGetter.validClients[testClientID] = testClient
        let testUser = OAuthUser(id: testUserID, username: testUsername, emailAddress: nil, password: testPassword.makeBytes())
        fakeUserManager.users.append(testUser)
        fakeTokenManager.accessTokenToReturn = accessToken
        fakeTokenManager.refreshTokenToReturn = refreshToken
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
    
    func testCorrectErrorWhenGrantTypeNotSupplied() throws {
        let response = try getPasswordResponse(grantType: nil)
        
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
        let response = try getPasswordResponse(grantType: grantType)
        
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
    
    func testCorrectErrorWhenUsernameNotSupplied() throws {
        let response = try getPasswordResponse(username: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'username' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorWhenPasswordNotSupplied() throws {
        let response = try getPasswordResponse(password: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'password' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorWhenClientIDNotSupplied() throws {
        let response = try getPasswordResponse(clientID: nil)
        
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

    func testCorrectErrorWhenClientIDNotValid() throws {
        let response = try getPasswordResponse(clientID: "UNKNOWN_CLIENT")
        
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
    
    func testCorrectErrorWhenClientDoesNotAuthenticate() throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(clientID: clientID, redirectURIs: ["https://api.brokenhands.io/callback"], clientSecret: "1234567890ABCD")
        fakeClientGetter.validClients[clientID] = clientWithSecret
        
        let response = try getPasswordResponse(clientID: clientID, clientSecret: "incorrectPassword")
        
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
    
    func testCorrectErrorIfClientSecretNotSentAndIsExpected() throws {
        let clientID = "ABCDEF"
        let clientWithSecret = OAuthClient(clientID: clientID, redirectURIs: ["https://api.brokenhands.io/callback"], clientSecret: "1234567890ABCD")
        fakeClientGetter.validClients[clientID] = clientWithSecret
        
        let response = try getPasswordResponse(clientID: clientID, clientSecret: nil)
        
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
    
    func testCorrectErrorWhenUserDoesNotExist() throws {
        let response = try getPasswordResponse(username: "UNKNOWN_USER")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
        XCTAssertEqual(responseJSON["error_description"], "Request had invalid credentials")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testCorrectErrorWhenPasswordIsIncorrect() throws {
        let response = try getPasswordResponse(password: "INCORRECT_PASSWORD")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_grant")
        XCTAssertEqual(responseJSON["error_description"], "Request had invalid credentials")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testThatTokenReceivedIfUserAuthenticated() throws {
        let response = try getPasswordResponse()
        
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
    }
    

    func testScopeSetOnTokenIfRequested() throws {
        let scope = "email create"
        
        let response = try getPasswordResponse(scope: scope)
        
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
        XCTAssertEqual(responseJSON["scope"]?.string, scope)
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessToken), let refreshToken = fakeTokenManager.getRefreshToken(refreshToken) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.scopes ?? [], ["email", "create"])
        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }

    func testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo() throws {
        let scope = "email edit"
        
        let response = try getPasswordResponse(scope: scope)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_scope")
        XCTAssertEqual(responseJSON["error_description"]?.string, "Request contained an invalid scope")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }

    func testCorrectErrorWhenRequestingUnknownScope() throws {
        let scope = "email unknown"
        
        let response = try getPasswordResponse(scope: scope)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_scope")
        XCTAssertEqual(responseJSON["error_description"]?.string, "Request contained an unknown scope")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }

    func testCorrectErrorWhen3rdParyClientTriesToUsePassword() throws {
        let newClientID = "AB1234"
        let newClient = OAuthClient(clientID: newClientID, redirectURIs: nil, firstParty: false)
        fakeClientGetter.validClients[newClientID] = newClient
        
        let response = try getPasswordResponse(clientID: newClientID, clientSecret: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "unauthorized_client")
        XCTAssertEqual(responseJSON["error_description"]?.string, "Password Credentials grant is not allowed")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testMessageLoggedForIncorrectLogin() throws {
        _ = try getPasswordResponse(password: "INCORRECT_PASSWORD")
        
        XCTAssertEqual(capturingLogger.logLevel, LogLevel.warning)
        XCTAssertEqual(capturingLogger.logMessage, "LOGIN WARNING: Invalid login attempt for user \(testUsername)")
    }
    
    func testUserIsAssociatedWithTokenID() throws {
        let response = try getPasswordResponse()
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        guard let token = fakeTokenManager.getAccessToken(responseJSON["access_token"]?.string ?? "") else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(token.userID, testUserID)
    }
    
    func testExpiryTimeIsSetOnAccessToken() throws {
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime
        
        let response = try getPasswordResponse()
        
        guard let accessTokenString = response.json?["access_token"]?.string else {
            XCTFail()
            return
        }
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.expiryTime, currentTime.addingTimeInterval(3600))
    }
    
    func testThatRefreshTokenHasCorrectClientIDSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getPasswordResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.clientID, testClientID)
    }
    
    func testThatRefreshTokenHasNoScopesIfNoneRequested() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getPasswordResponse(scope: nil)
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertNil(refreshToken.scopes)
    }
    
    func testThatRefreshTokenHasCorrectScopesIfSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getPasswordResponse(scope: "email create")
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }
    
    func testUserIDSetOnRefreshToken() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getPasswordResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.userID, testUserID)
    }
    
    func testClientNotConfiguredWithAccessToPasswordFlowCantAccessIt() throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedSecret = "client-secret"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: nil, clientSecret: unauthorizedSecret, validScopes: nil, confidential: true, firstParty: true, allowedGrantTypes: [.authorization, .clientCredentials, .implicit, .refresh])
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient
        
        let response = try getPasswordResponse(clientID: unauthorizedID, clientSecret: unauthorizedSecret)
        
        XCTAssertEqual(response.status, .forbidden)
    }
    
    func testClientConfiguredWithAccessToPasswordFlowCanAccessIt() throws {
        let authorizedID = "not-allowed"
        let authorizedSecret = "client-secret"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: nil, clientSecret: authorizedSecret, validScopes: nil, confidential: true, firstParty: true, allowedGrantTypes: [.password])
        fakeClientGetter.validClients[authorizedID] = authorizedClient
        
        let response = try getPasswordResponse(clientID: authorizedID, clientSecret: authorizedSecret)
        
        XCTAssertEqual(response.status, .ok)
    }
    
    // MARK: - Private
    
    func getPasswordResponse(grantType: String? = "password", username: String? = "testUser", password: String? = "testPassword", clientID: String? = "ABCDEF", clientSecret: String? = "01234567890", scope: String? = nil) throws -> Response {
        return try TestDataBuilder.getTokenRequestResponse(with: drop, grantType: grantType, clientID: clientID, clientSecret: clientSecret, scope: scope, username: username, password: password)
    }

}
