import XCTest
import OAuth
import Vapor

class TokenIntrospectionTests: XCTestCase {
    // MARK: - All Tests
    
    static var allTests = [
        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
        ("testCorrectErrorWhenTokenParameterNotSuppliedInRequest", testCorrectErrorWhenTokenParameterNotSuppliedInRequest),
        ]
    
    // MARK: - Properties
    
    var drop: Droplet!
//    let fakeClientGetter = FakeClientGetter()
//    let fakeUserManager = FakeUserManager()
    let fakeTokenManager = FakeTokenManager()
//    let capturingLogger = CapturingLogger()
//    let testClientID = "ABCDEF"
//    let testClientSecret = "01234567890"
//    let testUsername = "testUser"
//    let testPassword = "testPassword"
//    let testUserID: Identifier = "ABCD-FJUH-31232"
//    let accessToken = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
//    let refreshToken = "ABCDEFGHIJLMNOP1234567890"
    let scope1 = "email"
    let scope2 = "create"
    
    // MARK: - Overrides
    
    override func setUp() {
        drop = try! TestDataBuilder.getOAuthDroplet(tokenManager: fakeTokenManager, validScopes: [scope1, scope2])
//
//        let testClient = OAuthClient(clientID: testClientID, redirectURIs: nil, clientSecret: testClientSecret, validScopes: [scope1, scope2], firstParty: true)
//        fakeClientGetter.validClients[testClientID] = testClient
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
        let request = Request(method: .post, uri: "/oauth/token_info")
        let response = try drop.respond(to: request)
        
        guard let responseJSON = response.json else {
            XCTFail()
            return
        }
        
        XCTAssertEqual(response.status, .badRequest)
        XCTAssertEqual(responseJSON["error"]?.string, "missing_token")
        XCTAssertEqual(responseJSON["error_description"]?.string, "The token parameter is required")
    }

}
