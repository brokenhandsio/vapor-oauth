//
//  DeviceCodeGrantTests.swift
//
//
//  Created by Vamsi Madduluri on 24/08/23.
//

import XCTVapor
@testable import VaporOAuth

class DeviceCodeTokenTests: XCTestCase {
    struct ErrorResponse: Decodable {
        var error: String
        var errorDescription: String
        
        enum CodingKeys: String, CodingKey {
            case error
            case errorDescription = "error_description"
        }
    }
    
    struct SuccessResponse: Decodable {
        var tokenType: String?
        var expiresIn: Int?
        var accessToken: String?
        var refreshToken: String?
        var scope: String?
        
        enum CodingKeys: String, CodingKey {
            case tokenType = "token_type"
            case expiresIn = "expires_in"
            case accessToken = "access_token"
            case refreshToken = "refresh_token"
            case scope
        }
    }
    
    // MARK: - Properties
    
    var app: Application!
    var fakeClientGetter: FakeClientGetter!
    var fakeDeviceCodeManager: FakeCodeManager!
    var fakeTokenManager: FakeTokenManager!
    
    let testClientID = "1234567890"
    let testDeviceCodeID = "DEVICE_CODE_ID"
    let userID = "the-user-id"
    let scopes = ["email", "create"]
    
    // MARK: - Overrides
    
    override func setUp() async throws {
        fakeClientGetter = FakeClientGetter()
        fakeDeviceCodeManager = FakeCodeManager()
        fakeTokenManager = FakeTokenManager()
        
        let oauthClient = OAuthClient(
            clientID: testClientID,
            redirectURIs: ["https://api.brokenhands.io/callback"],
            clientSecret: nil,
            allowedGrantType: .deviceCode
        )
        fakeClientGetter.validClients[testClientID] = oauthClient
        
        let testDeviceCode = OAuthDeviceCode(
            deviceCodeID: testDeviceCodeID,
            userCode: "USER_CODE",
            clientID: testClientID,
            userID: userID,
            expiryDate: Date().addingTimeInterval(60),
            scopes: scopes
        )
        
        fakeDeviceCodeManager.deviceCodes[testDeviceCodeID] = testDeviceCode
        
        app = try TestDataBuilder.getOAuth2Application(
            codeManager: fakeDeviceCodeManager,
            tokenManager: fakeTokenManager,
            clientRetriever: fakeClientGetter
        )
    }
    
    override func tearDown() async throws {
        app.shutdown()
        try await super.tearDown()
    }
    
    // MARK: - Tests
    
    func testCorrectErrorAndHeadersReceivedWhenNoGrantTypeSent() async throws {
        let response = try await getDeviceCodeResponse(grantType: nil)
        
        XCTAssertEqual(response.status, .badRequest)
        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_request")
        XCTAssertEqual(errorResponse.errorDescription, "Request was missing the 'grant_type' parameter")
    }
    
    func testCorrectErrorAndHeadersReceivedWhenIncorrectGrantTypeSet() async throws {
        let grantType = "some_unknown_type"
        let response = try await getDeviceCodeResponse(grantType: grantType)
        
        XCTAssertEqual(response.status, .badRequest)
        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "unsupported_grant_type")
        XCTAssertEqual(errorResponse.errorDescription, "This server does not support the 'some_unknown_type' grant type")
    }
    
    func testCorrectErrorAndHeadersReceivedWhenNoDeviceCodeSent() async throws {
        let response = try await getDeviceCodeResponse(deviceCode: nil)
        
        XCTAssertEqual(response.status, .badRequest)
        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "invalid_request")
        XCTAssertEqual(errorResponse.errorDescription, "Request was missing the 'device_code' parameter")
    }
    
    func testCorrectErrorCodeWhenDeviceCodeIsExpired() async throws {
        let expiredDeviceCodeID = "expiredDeviceCodeID"
        let expiredDeviceCode = OAuthDeviceCode(
            deviceCodeID: expiredDeviceCodeID,
            userCode: "USER_CODE",
            clientID: testClientID,
            userID: userID,
            expiryDate: Date().addingTimeInterval(-60), // Expired 60 seconds ago
            scopes: scopes
        )
        fakeDeviceCodeManager.deviceCodes[expiredDeviceCodeID] = expiredDeviceCode

        let response = try await getDeviceCodeResponse(deviceCode: expiredDeviceCodeID)

        XCTAssertEqual(response.status, .badRequest)
        let errorResponse = try response.content.decode(ErrorResponse.self)
        XCTAssertEqual(errorResponse.error, "expired_token")
        XCTAssertEqual(errorResponse.errorDescription, "The device code provided was invalid or expired")
    }
    
    func testThatCorrectResponseReceivedWhenCorrectRequestSent() async throws {
        let response = try await getDeviceCodeResponse()
        
        XCTAssertEqual(response.status, .ok)
        let successResponse = try response.content.decode(SuccessResponse.self)
        XCTAssertEqual(successResponse.tokenType, "bearer")
        XCTAssertNotNil(successResponse.accessToken)
        XCTAssertNotNil(successResponse.expiresIn)
        XCTAssertEqual(successResponse.scope, scopes.joined(separator: " "))
    }
    
    // MARK: - Private
    
    private func getDeviceCodeResponse(
        grantType: String? = "urn:ietf:params:oauth:grant-type:device_code",
        deviceCode: String? = "DEVICE_CODE_ID",
        clientID: String? = "1234567890"
    ) async throws -> XCTHTTPResponse {
        return try await TestDataBuilder.getTokenRequestResponse(
            with: app,
            grantType: grantType,
            clientID: clientID,
            clientSecret: nil,
            deviceCode: deviceCode
        )
    }

}
