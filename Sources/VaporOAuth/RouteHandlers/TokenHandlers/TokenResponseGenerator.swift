import Vapor
import HTTP

struct TokenResponseGenerator {
    func createResponse(error: String, description: String, status: Status = .badRequest) throws -> Response {
        var json = JSON()
        try json.set(OAuthResponseParameters.error, error)
        try json.set(OAuthResponseParameters.errorDescription, description)

        return try createResponseForToken(status: status, json: json)
    }

    func createResponse(accessToken: AccessToken, refreshToken: RefreshToken?,
                        expires: Int, scope: String?) throws -> Response {

        var json = JSON()
        try json.set(OAuthResponseParameters.tokenType, "bearer")
        try json.set(OAuthResponseParameters.expires, expires)
        try json.set(OAuthResponseParameters.accessToken, accessToken.tokenString)

        if let refreshToken = refreshToken {
            try json.set(OAuthResponseParameters.refreshToken, refreshToken.tokenString)
        }

        if let scope = scope {
            try json.set(OAuthResponseParameters.scope, scope)
        }

        return try createResponseForToken(status: .ok, json: json)
    }

    private func createResponseForToken(status: Status, json: JSON) throws -> Response {
        let response = try Response(status: status, json: json)

        response.headers[.pragma] = "no-cache"
        response.headers[.cacheControl] = "no-store"

        return response
    }

}
