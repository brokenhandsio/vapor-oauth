import Vapor

struct DeviceCodeTokenHandler {

    let clientValidator: ClientValidator
    let tokenManager: TokenManager
    let tokenResponseGenerator: TokenResponseGenerator

    func handleDeviceCodeTokenRequest(_ request: Request) async throws -> Response {
        guard let deviceCodeString: String = request.content[OAuthRequestParameters.deviceCode] else {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                                             description: "Request was missing the 'device_code' parameter")
        }

        guard let clientID: String = request.content[OAuthRequestParameters.clientID] else {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidRequest,
                                                             description: "Request was missing the 'client_id' parameter")
        }

        do {
            try await clientValidator.authenticateClient(clientID: clientID, clientSecret: nil,
                                                         grantType: .deviceCode)
        } catch {
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidClient,
                                                             description: "Request had invalid client credentials", status: .unauthorized)
        }

        guard let deviceCode = try await tokenManager.getDeviceCode(deviceCodeString),
              !deviceCode.isExpired else {
            let errorDescription = "The device code provided was invalid or expired"
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidGrant,
                                                             description: errorDescription)
        }

        try await tokenManager.deviceCodeUsed(deviceCode)

        let scopes = deviceCode.scopes
        let expiryTime = 3600

        let (access, refresh) = try await tokenManager.generateAccessRefreshTokens(
            clientID: clientID, userID: deviceCode.userID,
            scopes: scopes,
            accessTokenExpiryTime: expiryTime
        )

        return try tokenResponseGenerator.createResponse(accessToken: access, refreshToken: refresh, expires: Int(expiryTime),
                                                         scope: scopes?.joined(separator: " "))
    }
}
