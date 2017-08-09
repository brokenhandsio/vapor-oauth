#if os(Linux)

import XCTest
@testable import OAuthTests

XCTMain([
    // OAuthTests
    testCase(AuthorizationRequestTests.allTests),
    testCase(AuthorizationResponseTests.allTests),
    testCase(AuthorizationCodeTokenTests.allTests),
    testCase(PasswordGrantTokenTests.allTests),
    testCase(ClientCredentialsTokenTests.allTests),
    testCase(TokenRefreshTests.allTests),
    testCase(ImplicitGrantTests.allTests),
    testCase(AuthCodeResourceServerTests.allTests),
    testCase(TokenIntrospectionTests.allTests),
])

#endif
