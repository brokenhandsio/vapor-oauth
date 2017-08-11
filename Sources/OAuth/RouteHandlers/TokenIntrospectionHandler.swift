import HTTP
import JSON
import Foundation

struct TokenIntrospectionHandler {

    let clientValidator: ClientValidator
    let tokenManager: TokenManager
    let userManager: UserManager

    func handleRequest(_ req: Request) throws -> ResponseRepresentable {

        guard let tokenString = req.data[OAuthRequestParameters.token]?.string else {
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
        var username: String? = nil

        if let userID = token.userID {
            if let user = userManager.getUser(userID: userID) {
                username = user.username
            }
        }

        return try createTokenResponse(active: true, expiryDate: token.expiryTime, clientID: token.clientID,
                                       scopes: scopes, username: username)
    }

    func createTokenResponse(active: Bool, expiryDate: Date?, clientID: String?, scopes: String? = nil,
                             username: String? = nil) throws -> Response {
        var json = JSON()
        try json.set(OAuthResponseParameters.active, active)

        if let clientID = clientID {
            try json.set(OAuthResponseParameters.clientID, clientID)
        }

        if let scopes = scopes {
            try json.set(OAuthResponseParameters.scope, scopes)
        }

        if let username = username {
            try json.set(OAuthResponseParameters.username, username)
        }

        if let expiryDate = expiryDate {
            try json.set(OAuthResponseParameters.expiry, Int(expiryDate.timeIntervalSince1970))
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
