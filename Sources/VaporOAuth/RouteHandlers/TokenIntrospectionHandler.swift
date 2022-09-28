import Vapor

struct TokenIntrospectionHandler {
    let clientValidator: ClientValidator
    let tokenManager: TokenManager
    let userManager: UserManager

    func handleRequest(_ req: Request) async throws -> Response {

        guard let tokenString: String = req.content[OAuthRequestParameters.token] else {
            return try createErrorResponse(status: .badRequest,
                                           errorMessage: OAuthResponseParameters.ErrorType.missingToken,
                                           errorDescription: "The token parameter is required")
        }

        guard let token = tokenManager.getAccessToken(tokenString) else {
            return try createTokenResponse(active: false, expiryDate: nil, clientID: nil)
        }

        guard token.expiryTime >= Date() else {
            return try createTokenResponse(active: false, expiryDate: nil, clientID: nil)
        }

        let scopes = token.scopes?.joined(separator: " ")
        var user: OAuthUser? = nil

        if let userID = token.userID {
            if let tokenUser = userManager.getUser(userID: userID) {
                user = tokenUser
            }
        }

        return try createTokenResponse(active: true, expiryDate: token.expiryTime, clientID: token.clientID,
                                       scopes: scopes, user: user)
    }

    func createTokenResponse(active: Bool, expiryDate: Date?, clientID: String?, scopes: String? = nil,
                             user: OAuthUser? = nil) throws -> Response {
        var jsonDictionary = [OAuthResponseParameters.active: active] as [String: Any]

        if let clientID = clientID {
            jsonDictionary[OAuthResponseParameters.clientID] = clientID
        }

        if let scopes = scopes {
            jsonDictionary[OAuthResponseParameters.scope] = scopes
        }

        if let user = user {
            jsonDictionary[OAuthResponseParameters.userID] = user.id
            jsonDictionary[OAuthResponseParameters.username] = user.username
            if let email = user.emailAddress {
                jsonDictionary[OAuthResponseParameters.email] = email
            }
        }

        if let expiryDate = expiryDate {
            jsonDictionary[OAuthResponseParameters.expiry] = Int(expiryDate.timeIntervalSince1970)
        }

        let response = Response(status: .ok)
        response.body = try .init(data: JSONSerialization.data(withJSONObject: jsonDictionary))
        return response
    }

    func createErrorResponse(status: HTTPStatus, errorMessage: String, errorDescription: String) throws -> Response {
        let response = Response(status: status)
        let jsonDictionary = [
            OAuthResponseParameters.error: errorMessage,
            OAuthResponseParameters.errorDescription: errorDescription
        ]
        response.body = try .init(data: JSONSerialization.data(withJSONObject: jsonDictionary))
        return response
    }
}
