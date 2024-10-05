import Vapor

struct TokenResponseGenerator {
    func createResponse(error: String, description: String, status: HTTPStatus = .badRequest) throws -> Response {
        let jsonDictionary = [
            OAuthResponseParameters.error: error,
            OAuthResponseParameters.errorDescription: description,
        ]
        let json = try JSONSerialization.data(withJSONObject: jsonDictionary)
        return try createResponseForToken(status: status, jsonData: json)
    }

    func createResponse(
        accessToken: AccessToken,
        refreshToken: RefreshToken?,
        expires: Int,
        scope: String?
    ) throws -> Response {
        var jsonDictionary =
            [
                OAuthResponseParameters.tokenType: "bearer",
                OAuthResponseParameters.expires: expires,
                OAuthResponseParameters.accessToken: accessToken.tokenString,
            ] as [String: Any]

        if let refreshToken = refreshToken {
            jsonDictionary[OAuthResponseParameters.refreshToken] = refreshToken.tokenString
        }

        if let scope = scope {
            jsonDictionary[OAuthResponseParameters.scope] = scope
        }

        let json = try JSONSerialization.data(withJSONObject: jsonDictionary)
        return try createResponseForToken(status: .ok, jsonData: json)
    }

    private func createResponseForToken(status: HTTPStatus, jsonData: Data) throws -> Response {
        let response = Response(status: status)

        response.body = .init(data: jsonData)
        response.headers.contentType = .json

        response.headers.replaceOrAdd(name: "pragma", value: "no-cache")
        response.headers.cacheControl = HTTPHeaders.CacheControl(noStore: true)

        return response
    }

}
