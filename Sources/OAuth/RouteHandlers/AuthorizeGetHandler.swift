import HTTP
import Vapor
import Crypto

struct AuthorizeGetHandler {

    let authorizeHandler: AuthorizeHandler
    let clientValidator: ClientValidator

    func handleRequest(request: Request) throws -> ResponseRepresentable {

        guard let clientID = request.query?[OAuthRequestParameters.clientID]?.string else {
            return try authorizeHandler.handleAuthorizationError(.invalidClientID)
        }

        guard let redirectURIString = request.query?[OAuthRequestParameters.redirectURI]?.string else {
            return try authorizeHandler.handleAuthorizationError(.invalidRedirectURI)
        }

        let scopes: [String]

        if let scopeQuery = request.query?[OAuthRequestParameters.scope]?.string {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = []
        }

        let state = request.query?[OAuthRequestParameters.state]?.string

        guard let responseType = request.query?[OAuthRequestParameters.responseType]?.string else {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                       errorDescription: "Request+was+missing+the+response_type+parameter", state: state)
        }

        guard responseType == ResponseType.code || responseType == ResponseType.token else {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                       errorDescription: "invalid+response+type", state: state)
        }

        do {
            try clientValidator.validateClient(clientID: clientID, responseType: responseType,
                                               redirectURI: redirectURIString, scopes: scopes)
        } catch AuthorizationError.invalidClientID {
            return try authorizeHandler.handleAuthorizationError(.invalidClientID)
        } catch AuthorizationError.invalidRedirectURI {
            return try authorizeHandler.handleAuthorizationError(.invalidRedirectURI)
        } catch ScopeError.unknown {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+unknown", state: state)
        } catch ScopeError.invalid {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+invalid", state: state)
        } catch AuthorizationError.confidentialClientTokenGrant {
            return createErrorResponse(redirectURI: redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                       errorDescription: "token+grant+disabled+for+confidential+clients", state: state)
        } catch AuthorizationError.httpRedirectURI {
            return try authorizeHandler.handleAuthorizationError(.httpRedirectURI)
        }

        let redirectURI = URIParser.shared.parse(bytes: redirectURIString.makeBytes())

        let csrfToken = try Random.bytes(count: 32).hexString

        guard let session = request.session else {
            throw Abort.badRequest
        }

        try session.data.set(SessionData.csrfToken, csrfToken)
        let authorizationRequestObject = AuthorizationRequestObject(responseType: responseType, clientID: clientID,
                                                                    redirectURI: redirectURI, scope: scopes, state: state,
                                                                    csrfToken: csrfToken)

        return try authorizeHandler.handleAuthorizationRequest(request, authorizationRequestObject: authorizationRequestObject)
    }

    private func createErrorResponse(redirectURI: String, errorType: String, errorDescription: String,
                                     state: String?) -> Response {
        var redirectString = "\(redirectURI)?error=\(errorType)&error_description=\(errorDescription)"

        if let state = state {
            redirectString += "&state=\(state)"
        }

        return Response(redirect: redirectString)
    }
}
