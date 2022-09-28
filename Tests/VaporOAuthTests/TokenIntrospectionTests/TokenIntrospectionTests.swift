//import XCTest
//import VaporOAuth
//import Vapor
//import Foundation
//
//class TokenIntrospectionTests: XCTestCase {
//    // MARK: - All Tests
//    
//    static var allTests = [
//        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
//        ("testCorrectErrorWhenTokenParameterNotSuppliedInRequest", testCorrectErrorWhenTokenParameterNotSuppliedInRequest),
//        ("testCorrectErrorWhenNoAuthorisationSuppliied", testCorrectErrorWhenNoAuthorisationSuppliied),
//        ("testCorrectErrorWhenInvalidAuthorisationSupplied", testCorrectErrorWhenInvalidAuthorisationSupplied),
//        ("testCorrectErrorWhenInvalidUsernnameSuppliedForAuthorisation", testCorrectErrorWhenInvalidUsernnameSuppliedForAuthorisation),
//        ("testCorrectErrorWhenInvalidPasswordSuppliedForAuthorisation", testCorrectErrorWhenInvalidPasswordSuppliedForAuthorisation),
//        ("testThatInvalidTokenReturnsInactive", testThatInvalidTokenReturnsInactive),
//        ("testThatExpiredTokenReturnsInactive", testThatExpiredTokenReturnsInactive),
//        ("testThatValidTokenReturnsActive", testThatValidTokenReturnsActive),
//        ("testThatScopeReturnedInReponseIfTokenHasScope", testThatScopeReturnedInReponseIfTokenHasScope),
//        ("testCliendIDReturnedInTokenResponse", testCliendIDReturnedInTokenResponse),
//        ("testUsernameReturnedInTokenResponseIfTokenHasAUser", testUsernameReturnedInTokenResponseIfTokenHasAUser),
//        ("testTokenExpiryReturnedInResponse", testTokenExpiryReturnedInResponse),
//        ]
//    
//    
//    // MARK: - Properties
//    
//    var drop: Droplet!
//    let fakeTokenManager = FakeTokenManager()
//    let fakeUserManager = FakeUserManager()
//    let fakeResourceServerRetriever = FakeResourceServerRetriever()
//    let testClientID = "ABCDEF"
//    let testClientSecret = "01234567890"
//    let accessToken = "ABDEFGHIJKLMNO01234567890"
//    let scope1 = "email"
//    let scope2 = "create"
//    let resourceServerName = "brokenhands-users"
//    let resourceServerPassword = "users"
//    let clientID = "some-client"
//    
//    // MARK: - Overrides
//    
//    override func setUp() {
//        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, userManager: fakeUserManager, validScopes: [scope1, scope2], resourceServerRetriever: fakeResourceServerRetriever)
//
//        let resourceServer = OAuthResourceServer(username: resourceServerName, password: resourceServerPassword.makeBytes())
//        fakeResourceServerRetriever.resourceServers[resourceServerName] = resourceServer
//        
//        let validToken = AccessToken(tokenString: accessToken, clientID: clientID, userID: nil, expiryTime: Date().addingTimeInterval(60))
//        fakeTokenManager.accessTokens[accessToken] = validToken
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
//    func testCorrectErrorWhenTokenParameterNotSuppliedInRequest() throws {
//        let response = try getInfoResponse(token: nil)
////        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .badRequest)
//        XCTAssertEqual(responseJSON["error"]?.string, "missing_token")
//        XCTAssertEqual(responseJSON["error_description"]?.string, "The token parameter is required")
//    }
//    
//    func testCorrectErrorWhenNoAuthorisationSuppliied() throws {
//        let response = try getInfoResponse(authHeader: nil)
//        
//        XCTAssertEqual(response.status, .unauthorized)
//    }
//    
//    func testCorrectErrorWhenInvalidAuthorisationSupplied() throws {
//        let response = try getInfoResponse(authHeader: "INVALID")
//        
//        XCTAssertEqual(response.status, .unauthorized)
//    }
//    
//    func testCorrectErrorWhenInvalidUsernnameSuppliedForAuthorisation() throws {
//        let header = "UNKOWNUSER:\(resourceServerPassword)".makeBytes().base64Encoded.makeString()
//        let response = try getInfoResponse(authHeader: header)
//        
//        XCTAssertEqual(response.status, .unauthorized)
//    }
//    
//    func testCorrectErrorWhenInvalidPasswordSuppliedForAuthorisation() throws {
//        let header = "\(resourceServerName):SOMEPASSWORD".makeBytes().base64Encoded.makeString()
//        let response = try getInfoResponse(authHeader: header)
//        
//        XCTAssertEqual(response.status, .unauthorized)
//    }
//    
//    func testThatInvalidTokenReturnsInactive() throws {
//        let response = try getInfoResponse(token: "UNKNOWN_TOKEN")
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, false)
//    }
//    
//    func testThatExpiredTokenReturnsInactive() throws {
//        let tokenString = "EXPIRED_TOKEN"
//        let expiredToken = AccessToken(tokenString: tokenString, clientID: testClientID, userID: nil, expiryTime: Date().addingTimeInterval(-60))
//        fakeTokenManager.accessTokens[tokenString] = expiredToken
//        let response = try getInfoResponse(token: tokenString)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, false)
//    }
//    
//    func testThatValidTokenReturnsActive() throws {
//        let response = try getInfoResponse()
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, true)
//    }
//    
//    func testThatScopeReturnedInReponseIfTokenHasScope() throws {
//        let tokenString = "VALID_TOKEN"
//        let validToken = AccessToken(tokenString: tokenString, clientID: clientID, userID: nil, scopes: ["email", "profile"], expiryTime: Date().addingTimeInterval(60))
//        fakeTokenManager.accessTokens[tokenString] = validToken
//        
//        let response = try getInfoResponse(token: tokenString)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, true)
//        XCTAssertEqual(responseJSON["scope"]?.string, "email profile")
//    }
//    
//    func testCliendIDReturnedInTokenResponse() throws {
//        let response = try getInfoResponse()
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, true)
//        XCTAssertEqual(responseJSON["client_id"]?.string, clientID)
//    }
//    
//    func testUsernameReturnedInTokenResponseIfTokenHasAUser() throws {
//        let userID: Identifier = 123
//        let username = "hansolo"
//        let tokenString = "VALID_TOKEN"
//        let validToken = AccessToken(tokenString: tokenString, clientID: clientID, userID: userID, expiryTime: Date().addingTimeInterval(60))
//        fakeTokenManager.accessTokens[tokenString] = validToken
//        let newUser = OAuthUser(userID: userID, username: username, emailAddress: "han@therebelalliance.com", password: "leia".makeBytes())
//        fakeUserManager.users.append(newUser)
//        
//        let response = try getInfoResponse(token: tokenString)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, true)
//        XCTAssertEqual(responseJSON["username"]?.string, username)
//    }
//    
//    func testTokenExpiryReturnedInResponse() throws {
//        let tokenString = "VALID_TOKEN"
//        let expiryDate = Date().addingTimeInterval(60)
//        let validToken = AccessToken(tokenString: tokenString, clientID: clientID, userID: nil, expiryTime: expiryDate)
//        fakeTokenManager.accessTokens[tokenString] = validToken
//        
//        let response = try getInfoResponse(token: tokenString)
//        
//        guard let responseJSON = response.json else {
//            XCTFail()
//            return
//        }
//        
//        XCTAssertEqual(response.status, .ok)
//        XCTAssertEqual(responseJSON["active"]?.bool, true)
//        XCTAssertEqual(responseJSON["exp"]?.int, Int(expiryDate.timeIntervalSince1970))
//    }
//    
//    // MARK: - Helper method
//    
//    // Auth Header is brokenhands-users:users Base64 encoded
//    func getInfoResponse(token: String? = "ABDEFGHIJKLMNO01234567890", authHeader: String? = "YnJva2VuaGFuZHMtdXNlcnM6dXNlcnM=") throws -> Response {
//        let request = Request(method: .post, uri: "/oauth/token_info")
//        
//        // TODO - try Form URL encoded
//        var json = JSON()
//        
//        if let authHeader = authHeader {
//            request.headers[.authorization] = "Basic \(authHeader)"
//        }
//        
//        if let token = token {
//            try json.set("token", token)
//        }
//        
//        request.json = json
//        
//        let response = try drop.respond(to: request)
//        return response
//    }
//
//}
