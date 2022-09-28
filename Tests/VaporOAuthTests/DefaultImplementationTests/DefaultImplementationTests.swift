//import XCTest
//@testable import VaporOAuth
//import Vapor
//
//class DefaultImplementationTests: XCTestCase {
//
//    // MARK: - All Tests
//
//    static var allTests = [
//        ("testLinuxTestSuiteIncludesAllTests", testLinuxTestSuiteIncludesAllTests),
//        ("testThatEmptyResourceServerRetrieverReturnsNilWhenGettingResourceServer", testThatEmptyResourceServerRetrieverReturnsNilWhenGettingResourceServer),
//        ("testThatEmptyUserManagerReturnsNilWhenAttemptingToAuthenticate", testThatEmptyUserManagerReturnsNilWhenAttemptingToAuthenticate),
//        ("testThatEmptyUserManagerReturnsNilWhenTryingToGetUser", testThatEmptyUserManagerReturnsNilWhenTryingToGetUser),
//        ("testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthError", testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthError),
//        ("testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthRequest", testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthRequest),
//        ("testThatEmptyCodeManagerReturnsNilWhenGettingCode", testThatEmptyCodeManagerReturnsNilWhenGettingCode),
//        ("testThatEmptyCodeManagerGeneratesEmptyStringAsCode", testThatEmptyCodeManagerGeneratesEmptyStringAsCode),
//        ("testThatCodeUsedDoesNothingInEmptyCodeManager", testThatCodeUsedDoesNothingInEmptyCodeManager),
//    ]
//
//
//    // MARK: - Properties
//
//
//    // MARK: - Overrides
//
//    override func setUp() {
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
//    func testThatEmptyResourceServerRetrieverReturnsNilWhenGettingResourceServer() {
//        let emptyResourceServerRetriever = EmptyResourceServerRetriever()
//
//        XCTAssertNil(emptyResourceServerRetriever.getServer("some username"))
//    }
//
//    func testThatEmptyUserManagerReturnsNilWhenAttemptingToAuthenticate() {
//        let emptyUserManager = EmptyUserManager()
//        XCTAssertNil(emptyUserManager.authenticateUser(username: "username", password: "password"))
//    }
//
//    func testThatEmptyUserManagerReturnsNilWhenTryingToGetUser() {
//        let emptyUserManager = EmptyUserManager()
//        let idenfitier: Identifier = "some-id"
//        XCTAssertNil(emptyUserManager.getUser(userID: idenfitier))
//    }
//
//    func testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthError() throws {
//        let emptyAuthHandler = EmptyAuthorizationHandler()
//
//        XCTAssertEqual(try emptyAuthHandler.handleAuthorizationError(.invalidClientID).makeResponse().body.bytes!, "".makeBytes())
//    }
//
//    func testThatEmptyAuthHandlerReturnsEmptyStringWhenHandlingAuthRequest() throws {
//        let emptyAuthHandler = EmptyAuthorizationHandler()
//        let request = Request(method: .post, uri: "/oauth/auth/")
//        let uri = URIParser.shared.parse(bytes: "https://api.brokenhands.io/callback".makeBytes())
//        let authRequestObject = AuthorizationRequestObject(responseType: "token", clientID: "client-ID", redirectURI: uri, scope: ["email"], state: "abcdef", csrfToken: "01234")
//
//        XCTAssertEqual(try emptyAuthHandler.handleAuthorizationRequest(request, authorizationRequestObject: authRequestObject).makeResponse().body.bytes!, "".makeBytes())
//    }
//
//    func testThatEmptyCodeManagerReturnsNilWhenGettingCode() {
//        let emptyCodeManager = EmptyCodeManager()
//        XCTAssertNil(emptyCodeManager.getCode("code"))
//    }
//
//    func testThatEmptyCodeManagerGeneratesEmptyStringAsCode() throws {
//        let emptyCodeManager = EmptyCodeManager()
//        let identifier: Identifier = "identifier"
//        XCTAssertEqual(try emptyCodeManager.generateCode(userID: identifier, clientID: "client-id", redirectURI: "https://api.brokenhands.io/callback", scopes: nil), "")
//    }
//
//    func testThatCodeUsedDoesNothingInEmptyCodeManager() {
//        let emptyCodeManager = EmptyCodeManager()
//        let identifier: Identifier = "identifier"
//        let code = OAuthCode(codeID: "id", clientID: "client-id", redirectURI: "https://api.brokenhands.io/callback", userID: identifier, expiryDate: Date(), scopes: nil)
//        emptyCodeManager.codeUsed(code)
//    }
//
//}
