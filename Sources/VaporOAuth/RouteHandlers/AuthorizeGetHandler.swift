import HTTP
import Vapor
import Crypto

struct AuthorizeGetHandler {

    let authorizeHandler: AuthorizeHandler
    let clientValidator: ClientValidator

    func handleRequest(request: Request) throws -> ResponseRepresentable {

        let (errorResponse, createdAuthRequestObject) = try validateRequest(request)

        if let errorResponseReturned = errorResponse {
            return errorResponseReturned
        }

        guard let authRequestObject = createdAuthRequestObject else {
            throw Abort.serverError
        }

        do {
            try clientValidator.validateClient(clientID: authRequestObject.clientID, responseType: authRequestObject.responseType,
                                               redirectURI: authRequestObject.redirectURIString, scopes: authRequestObject.scopes)
        } catch AuthorizationError.invalidClientID {
            return try authorizeHandler.handleAuthorizationError(.invalidClientID)
        } catch AuthorizationError.invalidRedirectURI {
            return try authorizeHandler.handleAuthorizationError(.invalidRedirectURI)
        } catch ScopeError.unknown {
            return createErrorResponse(redirectURI: authRequestObject.redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+unknown",
                                       state: authRequestObject.state)
        } catch ScopeError.invalid {
            return createErrorResponse(redirectURI: authRequestObject.redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+invalid",
                                       state: authRequestObject.state)
        } catch AuthorizationError.confidentialClientTokenGrant {
            return createErrorResponse(redirectURI: authRequestObject.redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                       errorDescription: "token+grant+disabled+for+confidential+clients",
                                       state: authRequestObject.state)
        } catch AuthorizationError.httpRedirectURI {
            return try authorizeHandler.handleAuthorizationError(.httpRedirectURI)
        }

        let redirectURI = URIParser.shared.parse(bytes: authRequestObject.redirectURIString.makeBytes())
        let csrfToken = try Random.bytes(count: 32).hexString

        guard let session = request.session else {
            throw Abort.badRequest
        }

        try session.data.set(SessionData.csrfToken, csrfToken)
        let authorizationRequestObject = AuthorizationRequestObject(responseType: authRequestObject.responseType,
                                                                    clientID: authRequestObject.clientID, redirectURI: redirectURI,
                                                                    scope: authRequestObject.scopes, state: authRequestObject.state,
                                                                    csrfToken: csrfToken)

        return try authorizeHandler.handleAuthorizationRequest(request, authorizationRequestObject: authorizationRequestObject)
    }

    private func validateRequest(_ request: Request) throws -> (ResponseRepresentable?, AuthorizationGetRequestObject?) {
        guard let clientID = request.query?[OAuthRequestParameters.clientID]?.string else {
            return (try authorizeHandler.handleAuthorizationError(.invalidClientID), nil)
        }

        guard let redirectURIString = request.query?[OAuthRequestParameters.redirectURI]?.string else {
            return (try authorizeHandler.handleAuthorizationError(.invalidRedirectURI), nil)
        }

        let scopes: [String]

        if let scopeQuery = request.query?[OAuthRequestParameters.scope]?.string {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = []
        }

        let state = request.query?[OAuthRequestParameters.state]?.string

        guard let responseType = request.query?[OAuthRequestParameters.responseType]?.string else {
            let errorResponse = createErrorResponse(redirectURI: redirectURIString,
                                                    errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                                    errorDescription: "Request+was+missing+the+response_type+parameter",
                                                    state: state)
            return (errorResponse, nil)
        }

        guard responseType == ResponseType.code || responseType == ResponseType.token else {
            let errorResponse = createErrorResponse(redirectURI: redirectURIString,
                                                    errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                                    errorDescription: "invalid+response+type", state: state)
            return (errorResponse, nil)
        }

        let authRequestObject = AuthorizationGetRequestObject(clientID: clientID, redirectURIString: redirectURIString,
                                                              scopes: scopes, state: state,
                                                              responseType: responseType)

        return (nil, authRequestObject)
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

struct AuthorizationGetRequestObject {
    let clientID: String
    let redirectURIString: String
    let scopes: [String]
    let state: String?
    let responseType: String
}
