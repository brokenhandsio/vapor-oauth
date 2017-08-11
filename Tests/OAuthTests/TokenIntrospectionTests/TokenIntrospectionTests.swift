import XCTest
import OAuth
import Vapor
import Foundation

class TokenIntrospectionTests: XCTestCase {
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testCorrectErrorWhenTokenParameterNotSuppliedInRequest", testCorrectErrorWhenTokenParameterNotSuppliedInRequest),
        ("testCorrectErrorWhenNoAuthorisationSuppliied", testCorrectErrorWhenNoAuthorisationSuppliied),
        ("testCorrectErrorWhenInvalidAuthorisationSupplied", testCorrectErrorWhenInvalidAuthorisationSupplied),
        ("testThatInvalidTokenReturnsInactive", testThatInvalidTokenReturnsInactive),
        ("testThatExpiredTokenReturnsInactive", testThatExpiredTokenReturnsInactive),
        ]
    
    // MARK: - Properties
    
    var drop: Droplet!
//    let fakeUserManager = FakeUserManager()
    let fakeTokenManager = FakeTokenManager()
    let fakeResourceServerRetriever = FakeResourceServerRetriever()
//    let capturingLogger = CapturingLogger()
    let testClientID = "ABCDEF"
    let testClientSecret = "01234567890"
//    let testUsername = "testUser"
//    let testPassword = "testPassword"
//    let testUserID: Identifier = "ABCD-FJUH-31232"
    let accessToken = "ABDEFGHIJKLMNO01234567890"
//    let refreshToken = "ABCDEFGHIJLMNOP1234567890"
    let scope1 = "email"
    let scope2 = "create"
    let resourceServerName = "brokenhands-users"
    
    // MARK: - Overrides
    
    override func setUp() {
        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, validScopes: [scope1, scope2], resourceServerRetriever: fakeResourceServerRetriever)

        let hashedPassword = try! BCryptHasher(cost: 10).make("users")
        let resourceServer = OAuthResourceServer(username: resourceServerName, password: hashedPassword)
        fakeResourceServerRetriever.resourceServers[resourceServerName] = resourceServer
//        let testUser = OAuthUser(userID: testUserID, username: testUsername, emailAddress: nil, password: testPassword.makeBytes())
//        fakeUserManager.users.append(testUser)
//        fakeTokenManager.accessTokenToReturn = accessToken
//        fakeTokenManager.refreshTokenToReturn = refreshToken
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
    
    func testCorrectErrorWhenTokenParameterNotSuppliedInRequest() throws {
        let response = try getInfoResponse(token: nil)
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "missing_token")
        XCTAssertEqual(responseJSON["error_description"]?.string, "The token parameter is required")
    }
    
    func testCorrectErrorWhenNoAuthorisationSuppliied() throws {
        let response = try getInfoResponse(authHeader: nil)
        
        XCTAssertEqual(response.status, .unauthorized)
    }
    
    func testCorrectErrorWhenInvalidAuthorisationSupplied() throws {
        let response = try getInfoResponse(authHeader: "INVALID")
        
        XCTAssertEqual(response.status, .unauthorized)
    }
    
    func testThatInvalidTokenReturnsInactive() throws {
        let response = try getInfoResponse(token: "UNKNOWN_TOKEN")
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON["active"]?.bool, false)
    }
    
    func testThatExpiredTokenReturnsInactive() throws {
        let tokenString = "EXPIRED_TOKEN"
        let expiredToken = AccessToken(tokenString: tokenString, clientID: testClientID, userID: nil, expiryTime: Date().addingTimeInterval(-60))
        fakeTokenManager.accessTokens[tokenString] = expiredToken
        let response = try getInfoResponse(token: tokenString)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .ok)
        XCTAssertEqual(responseJSON["active"]?.bool, false)
    }
    
    // MARK: - Helper method
    
    // Auth Header is brokenhands-users:users Base64 encoded
    func getInfoResponse(token: String? = "ABDEFGHIJKLMNO01234567890", authHeader: String? = "YnJva2VuaGFuZHMtdXNlcnM6dXNlcnM=") throws -> Response {
        let request = Request(method: .post, uri: "/oauth/token_info")
        
        // TODO - try Form URL encoded
        var json = JSON()
        
        if let authHeader = authHeader {
            request.headers[.authorization] = "Basic \(authHeader)"
        }
        
        if let token = token {
            try json.set("token", token)
        }
        
        request.json = json
        
        let response = try drop.respond(to: request)
        return response
    }

}
