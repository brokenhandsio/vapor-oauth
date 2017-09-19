import Vapor

struct AuthorizePostRequest {
    let user: OAuthUser
    let userID: Identifier
    let redirectURIBaseString: String
    let approveApplication: Bool
    let clientID: String
    let responseType: String
    let csrfToken: String
    let scopes: [String]?
}

struct AuthorizePostHandler {

    let tokenManager: TokenManager
    let codeManager: CodeManager
    let clientValidator: ClientValidator

    func handleRequest(request: Request) throws -> ResponseRepresentable {
        let requestObject = try validateAuthPostRequest(request)
        var redirectURI = requestObject.redirectURIBaseString

        do {
            try clientValidator.validateClient(clientID: requestObject.clientID, responseType: requestObject.responseType,
                               redirectURI: requestObject.redirectURIBaseString, scopes: requestObject.scopes)
        } catch is AbortError {
            throw Abort(.forbidden)
        } catch {
            throw Abort.badRequest
        }

        guard let session = request.session else {
            throw Abort.badRequest
        }

        guard session.data[SessionData.csrfToken]?.string == requestObject.csrfToken else {
            throw Abort.badRequest
        }

        if requestObject.approveApplication {
            if requestObject.responseType == ResponseType.token {
                let accessToken = try tokenManager.generateAccessToken(clientID: requestObject.clientID,
                                                                       userID: requestObject.userID,
                                                                       scopes: requestObject.scopes, expiryTime: 3600)
                redirectURI += "#token_type=bearer&access_token=\(accessToken.tokenString)&expires_in=3600"
            } else if requestObject.responseType == ResponseType.code {
                let generatedCode = try codeManager.generateCode(userID: requestObject.userID,
                                                                 clientID: requestObject.clientID,
                                                                 redirectURI: requestObject.redirectURIBaseString,
                                                                 scopes: requestObject.scopes)
                redirectURI += "?code=\(generatedCode)"
            } else {
                redirectURI += "?error=invalid_request&error_description=unknown+response+type"
            }
        } else {
            redirectURI += "?error=access_denied&error_description=user+denied+the+request"
        }

        if let requestedScopes = requestObject.scopes {
            if !requestedScopes.isEmpty {
                redirectURI += "&scope=\(requestedScopes.joined(separator: "+"))"
            }
        }

        if let state = request.query?[OAuthRequestParameters.state]?.string {
            redirectURI += "&state=\(state)"
        }

        return Response(redirect: redirectURI)
    }

    private func validateAuthPostRequest(_ request: Request) throws -> AuthorizePostRequest {
        guard let user = request.auth.authenticated(OAuthUser.self) else {
            throw Abort.unauthorized
        }

        guard let userID = user.id else {
            throw Abort.unauthorized
        }

        guard let redirectURIBaseString = request.query?[OAuthRequestParameters.redirectURI]?.string else {
            throw Abort.badRequest
        }

        guard let approveApplication = request.data[OAuthRequestParameters.applicationAuthorized]?.bool else {
            throw Abort.badRequest
        }

        guard let clientID = request.query?[OAuthRequestParameters.clientID]?.string else {
            throw Abort.badRequest
        }

        guard let responseType = request.query?[OAuthRequestParameters.responseType]?.string else {
            throw Abort.badRequest
        }

        guard let csrfToken = request.data[OAuthRequestParameters.csrfToken]?.string else {
            throw Abort.badRequest
        }

        let scopes: [String]?

        if let scopeQuery = request.query?[OAuthRequestParameters.scope]?.string {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = nil
        }

        return AuthorizePostRequest(user: user, userID: userID, redirectURIBaseString: redirectURIBaseString,
                                    approveApplication: approveApplication, clientID: clientID,
                                    responseType: responseType, csrfToken: csrfToken, scopes: scopes)
    }

}
