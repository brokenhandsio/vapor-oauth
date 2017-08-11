import HTTP
import JSON
import Foundation

struct TokenIntrospectionHandler {

    let clientValidator: ClientValidator
    let tokenManager: TokenManager

    func handleRequest(_ req: Request) throws -> ResponseRepresentable {

        guard let tokenString = req.data[OAuthRequestParameters.token]?.string else {
            return try createErrorResponse(status: .badRequest,
                                           errorMessage: OAuthResponseParameters.ErrorType.missingToken,
                                           errorDescription: "The token parameter is required")
        }

        guard let token = tokenManager.getAccessToken(tokenString) else {
            return try createTokenResponse(active: false, clientID: nil)
        }

        guard token.expiryTime >= Date() else {
            return try createTokenResponse(active: false, clientID: nil)
        }

        let scopes = token.scopes?.joined(separator: " ")

        return try createTokenResponse(active: true, clientID: token.clientID, scopes: scopes)
    }

    func createTokenResponse(active: Bool, clientID: String?, scopes: String? = nil) throws -> Response {
        var json = JSON()
        try json.set(OAuthResponseParameters.active, active)

        if let clientID = clientID {
            try json.set(OAuthResponseParameters.clientID, clientID)
        }

        if let scopes = scopes {
            try json.set(OAuthResponseParameters.scope, scopes)
        }

        let response = Response(status: .ok)
        response.json = json
        return response
    }

    func createErrorResponse(status: Status, errorMessage: String, errorDescription: String) throws -> Response {
        var json = JSON()
        try json.set(OAuthResponseParameters.error, errorMessage)
        try json.set(OAuthResponseParameters.errorDescription, errorDescription)
        let response = Response(status: status)
        response.json = json
        return response
    }
}
