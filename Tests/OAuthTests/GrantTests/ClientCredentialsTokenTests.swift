import XCTest
import OAuth
import Vapor
import Foundation

class ClientCredentialsTokenTests: XCTestCase {
    
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testCorrectErrorWhenGrantTypeNotSupplied", testCorrectErrorWhenGrantTypeNotSupplied),
        ("testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet", testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet),
        ("testCorrectErrorWhenClientIDNotSupplied", testCorrectErrorWhenClientIDNotSupplied),
        ("testCorrectErrorWhenClientIDNotValid", testCorrectErrorWhenClientIDNotValid),
        ("testCorrectErrorWhenClientDoesNotAuthenticate", testCorrectErrorWhenClientDoesNotAuthenticate),
        ("testCorrectErrorIfClientSecretNotSent", testCorrectErrorIfClientSecretNotSent),
        ("testThatTokenReceivedIfClientAuthenticated", testThatTokenReceivedIfClientAuthenticated),
        ("testScopeSetOnTokenIfRequested", testScopeSetOnTokenIfRequested),
        ("testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo", testCorrectErrorWhenReqeustingScopeApplicationDoesNotHaveAccessTo),
        ("testCorrectErrorWhenRequestingUnknownScope", testCorrectErrorWhenRequestingUnknownScope),
        ("testCorrectErrorWhenNonConfidentialClientTriesToUseCredentialsGrantType", testCorrectErrorWhenNonConfidentialClientTriesToUseCredentialsGrantType),
        ("testAccessTokenHasCorrectExpiryTime", testAccessTokenHasCorrectExpiryTime),
        ("testClientIDSetOnAccessTokenCorrectly", testClientIDSetOnAccessTokenCorrectly),
        ("testThatRefreshTokenHasCorrectClientIDSet", testThatRefreshTokenHasCorrectClientIDSet),
        ("testThatRefreshTokenHasNoScopesIfNoneRequested", testThatRefreshTokenHasNoScopesIfNoneRequested),
        ("testThatRefreshTokenHasCorrectScopesIfSet", testThatRefreshTokenHasCorrectScopesIfSet),
        ("testNoUserIDSetOnRefreshToken", testNoUserIDSetOnRefreshToken),
        ("testClientNotConfiguredWithAccessToClientCredentialsFlowCantAccessIt", testClientNotConfiguredWithAccessToClientCredentialsFlowCantAccessIt),
        ("testClientConfiguredWithAccessToClientCredentialsFlowCanAccessIt", testClientConfiguredWithAccessToClientCredentialsFlowCanAccessIt),
        ]
    
    // MARK: - Properties
    
    var drop: Droplet!
    let fakeClientGetter = FakeClientGetter()
    let fakeTokenManager = FakeTokenManager()
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
    let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    let refreshToken = "ABCDEFGHIJLMNOP1234567890"
    let scope1 = "email"
    let scope2 = "create"
    let scope3 = "edit"
    
    // MARK: - Overrides
    
    override func setUp() {
        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, clientRetriever: fakeClientGetter, validScopes: [scope1, scope2, scope3])
        
        let testClient = OAuthClient(clientID: testClientID, redirectURIs: nil, clientSecret: testClientSecret, validScopes: [scope1, scope2], confidential: true)
        fakeClientGetter.validClients[testClientID] = testClient
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
        let response = try getClientCredentialsResponse(grantType: nil)
        
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
        let response = try getClientCredentialsResponse(grantType: grantType)
        
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
    
    func testCorrectErrorWhenClientIDNotSupplied() throws {
        let response = try getClientCredentialsResponse(clientID: nil)
        
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
        let response = try getClientCredentialsResponse(clientID: "UNKNOWN_CLIENT")
        
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
        let response = try getClientCredentialsResponse(clientSecret: "incorrectPassword")
        
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
    
    func testCorrectErrorIfClientSecretNotSent() throws {
        let response = try getClientCredentialsResponse(clientSecret: nil)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "invalid_request")
        XCTAssertEqual(responseJSON["error_description"], "Request was missing the 'client_secret' parameter")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testThatTokenReceivedIfClientAuthenticated() throws {
        let response = try getClientCredentialsResponse()
        
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
        
        let response = try getClientCredentialsResponse(scope: scope)
        
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
        
        let response = try getClientCredentialsResponse(scope: scope)
        
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
        
        let response = try getClientCredentialsResponse(scope: scope)
        
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
    
    func testCorrectErrorWhenNonConfidentialClientTriesToUseCredentialsGrantType() throws {
        let newClientID = "1234"
        let newClientSecret = "1234567899"
        let newClient = OAuthClient(clientID: newClientID, redirectURIs: nil, clientSecret: newClientSecret, confidential: false)
        fakeClientGetter.validClients[newClientID] = newClient
        
        let response = try getClientCredentialsResponse(clientID: newClientID, clientSecret: newClientSecret)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "unauthorized_client")
        XCTAssertEqual(responseJSON["error_description"], "You are not authorized to use the Client Credentials grant type")
        XCTAssertEqual(response.headers[.cacheControl], "no-store")
        XCTAssertEqual(response.headers[.pragma], "no-cache")
    }
    
    func testAccessTokenHasCorrectExpiryTime() throws {
        let currentTime = Date()
        fakeTokenManager.currentTime = currentTime
        
        let response = try getClientCredentialsResponse()
        
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
    
    func testClientIDSetOnAccessTokenCorrectly() throws {
        let newClientString = "a-new-client"
        let newClient = OAuthClient(clientID: newClientString, redirectURIs: nil, clientSecret: testClientSecret, validScopes: [scope1, scope2], confidential: true)
        fakeClientGetter.validClients[newClientString] = newClient
        
        let response = try getClientCredentialsResponse(clientID: newClientString)
        
        guard let accessTokenString = response.json?["access_token"]?.string else {
            XCTFail()
            return
        }
        
        guard let accessToken = fakeTokenManager.getAccessToken(accessTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(accessToken.clientID, newClientString)
    }
    
    func testThatRefreshTokenHasCorrectClientIDSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getClientCredentialsResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.clientID, testClientID)
    }
    
    func testThatRefreshTokenHasNoScopesIfNoneRequested() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getClientCredentialsResponse(scope: nil)
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertNil(refreshToken.scopes)
    }
    
    func testThatRefreshTokenHasCorrectScopesIfSet() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getClientCredentialsResponse(scope: "email create")
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(refreshToken.scopes ?? [], ["email", "create"])
    }
    
    func testNoUserIDSetOnRefreshToken() throws {
        let refreshTokenString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        fakeTokenManager.refreshTokenToReturn = refreshTokenString
        
        _ = try getClientCredentialsResponse()
        
        guard let refreshToken = fakeTokenManager.getRefreshToken(refreshTokenString) else {
            XCTFail()
            return
        }
        
        XCTAssertNil(refreshToken.userID)
    }
    
    func testClientNotConfiguredWithAccessToClientCredentialsFlowCantAccessIt() throws {
        let unauthorizedID = "not-allowed"
        let unauthorizedSecret = "client-secret"
        let unauthorizedClient = OAuthClient(clientID: unauthorizedID, redirectURIs: nil, clientSecret: unauthorizedSecret, validScopes: nil, confidential: true, firstParty: true, allowedGrantTypes: [.authorization, .password, .implicit, .refresh])
        fakeClientGetter.validClients[unauthorizedID] = unauthorizedClient
        
        let response = try getClientCredentialsResponse(clientID: unauthorizedID, clientSecret: unauthorizedSecret)
        
        XCTAssertEqual(response.status, .forbidden)
    }
    
    func testClientConfiguredWithAccessToClientCredentialsFlowCanAccessIt() throws {
        let authorizedID = "not-allowed"
        let authorizedSecret = "client-secret"
        let authorizedClient = OAuthClient(clientID: authorizedID, redirectURIs: nil, clientSecret: authorizedSecret, validScopes: nil, confidential: true, firstParty: true, allowedGrantTypes: [.clientCredentials])
        fakeClientGetter.validClients[authorizedID] = authorizedClient
        
        let response = try getClientCredentialsResponse(clientID: authorizedID, clientSecret: authorizedSecret)
        
        XCTAssertEqual(response.status, .ok)
    }
            
    // MARK: - Private
    
    func getClientCredentialsResponse(grantType: String? = "client_credentials", clientID: String? = "ABCDEF", clientSecret: String? = "01234567890", scope: String? = nil) throws -> Response {
        return try TestDataBuilder.getTokenRequestResponse(with: drop, grantType: grantType, clientID: clientID, clientSecret: clientSecret, scope: scope)
    }

}
