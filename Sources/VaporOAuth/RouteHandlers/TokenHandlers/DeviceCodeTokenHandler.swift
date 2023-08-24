import Vapor

struct DeviceCodeTokenHandler {

    let clientValidator: ClientValidator
    let scopeValidator: ScopeValidator
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

        guard let deviceCode = try await tokenManager.getDeviceCode(deviceCodeString) else {
            let errorDescription = "The device code provided was invalid or expired"
            return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidGrant,
                                                             description: errorDescription)
        }

        if let scopes = deviceCode.scopes {
            do {
                try await scopeValidator.validateScope(clientID: clientID, scopes: scopes)
            } catch ScopeError.invalid, ScopeError.unknown {
                return try tokenResponseGenerator.createResponse(error: OAuthResponseParameters.ErrorType.invalidScope,
                                                                 description: "Request contained an invalid or unknown scope")
            }
        }

        try await tokenManager.deviceCodeUsed(deviceCode)

        let expiryTime = 3600

        let (access, refresh) = try await tokenManager.generateAccessRefreshTokens(
            clientID: clientID, userID: deviceCode.userID,
            scopes: deviceCode.scopes,
            accessTokenExpiryTime: expiryTime
        )

        return try tokenResponseGenerator.createResponse(accessToken: access, refreshToken: refresh, expires: Int(expiryTime),
                                                         scope: deviceCode.scopes?.joined(separator: " "))
    }
}
