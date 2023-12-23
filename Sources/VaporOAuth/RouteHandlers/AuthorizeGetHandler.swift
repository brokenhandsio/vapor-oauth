import Vapor

struct AuthorizeGetHandler {
    let authorizeHandler: AuthorizeHandler
    let clientValidator: ClientValidator
    
    func handleRequest(request: Request) async throws -> Response {
        let (errorResponse, createdAuthRequestObject) = try await validateRequest(request)
        
        if let errorResponseReturned = errorResponse {
            return errorResponseReturned
        }
        
        guard let authRequestObject = createdAuthRequestObject else {
            throw Abort(.internalServerError)
        }
        
        // Additional OpenID Connect specific validation
        if authRequestObject.responseType.contains(ResponseType.idToken) {
            // Validate nonce for OpenID Connect
            guard let nonce = authRequestObject.nonce else {
                return createErrorResponse(request: request,
                                           redirectURI: authRequestObject.redirectURIString,
                                           errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                           errorDescription: "Nonce is required for response type id_token",
                                           state: authRequestObject.state)
            }
            // Additional validation for nonce can be added here
        }
        
        do {
            try await clientValidator.validateClient(
                clientID: authRequestObject.clientID,
                responseType: authRequestObject.responseType,
                redirectURI: authRequestObject.redirectURIString,
                scopes: authRequestObject.scopes
            )
        } catch AuthorizationError.invalidClientID {
            return try await authorizeHandler.handleAuthorizationError(.invalidClientID)
        } catch AuthorizationError.invalidRedirectURI {
            return try await authorizeHandler.handleAuthorizationError(.invalidRedirectURI)
        } catch ScopeError.unknown {
            return createErrorResponse(request: request,
                                       redirectURI: authRequestObject.redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+unknown",
                                       state: authRequestObject.state)
        } catch ScopeError.invalid {
            return createErrorResponse(request: request,
                                       redirectURI: authRequestObject.redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.invalidScope,
                                       errorDescription: "scope+is+invalid",
                                       state: authRequestObject.state)
        } catch AuthorizationError.confidentialClientTokenGrant {
            return createErrorResponse(request: request,
                                       redirectURI: authRequestObject.redirectURIString,
                                       errorType: OAuthResponseParameters.ErrorType.unauthorizedClient,
                                       errorDescription: "token+grant+disabled+for+confidential+clients",
                                       state: authRequestObject.state)
        } catch AuthorizationError.httpRedirectURI {
            return try await authorizeHandler.handleAuthorizationError(.httpRedirectURI)
        }
        
        let redirectURI = URI(stringLiteral: authRequestObject.redirectURIString)
        
        let csrfToken = [UInt8].random(count: 32).hex
        
        let codeChallenge = authRequestObject.codeChallenge
        let codeChallengeMethod = authRequestObject.codeChallengeMethod
        
        request.session.data[SessionData.csrfToken] = csrfToken
        
        let authorizationRequestObject = AuthorizationRequestObject(
            responseType: authRequestObject.responseType,
            clientID: authRequestObject.clientID,
            redirectURI: redirectURI,
            scope: authRequestObject.scopes,
            state: authRequestObject.state,
            csrfToken: csrfToken,
            codeChallenge: codeChallenge,
            codeChallengeMethod: codeChallengeMethod,
            nonce: authRequestObject.nonce
        )
        
        return try await authorizeHandler.handleAuthorizationRequest(request, authorizationRequestObject: authorizationRequestObject)
    }
    
    private func validateRequest(_ request: Request) async throws -> (Response?, AuthorizationGetRequestObject?) {
        guard let clientID: String = request.query[OAuthRequestParameters.clientID] else {
            return (try await authorizeHandler.handleAuthorizationError(.invalidClientID), nil)
        }
        
        guard let redirectURIString: String = request.query[OAuthRequestParameters.redirectURI] else {
            return (try await authorizeHandler.handleAuthorizationError(.invalidRedirectURI), nil)
        }
        
        let scopes: [String]
        
        if let scopeQuery: String = request.query[OAuthRequestParameters.scope] {
            scopes = scopeQuery.components(separatedBy: " ")
        } else {
            scopes = []
        }
        
        let state: String? = request.query[OAuthRequestParameters.state]
        
        guard let responseType: String = request.query[OAuthRequestParameters.responseType] else {
            let errorResponse = createErrorResponse(request: request,
                                                    redirectURI: redirectURIString,
                                                    errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                                    errorDescription: "Request+was+missing+the+response_type+parameter",
                                                    state: state)
            return (errorResponse, nil)
        }
        
        guard responseType == ResponseType.code || responseType == ResponseType.token || responseType == ResponseType.idToken || responseType == ResponseType.tokenAndIdToken else {
            let errorResponse = createErrorResponse(request: request,
                                                    redirectURI: redirectURIString,
                                                    errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                                    errorDescription: "invalid+response+type", state: state)
            return (errorResponse, nil)
        }
        
        let codeChallenge: String? = request.query[OAuthRequestParameters.codeChallenge]
        let codeChallengeMethod: String? = request.query[OAuthRequestParameters.codeChallengeMethod]
        
        // PKCE Validation
        if let codeChallenge = codeChallenge {
            if let codeChallengeMethod = codeChallengeMethod {
                if !(codeChallengeMethod == "plain" || codeChallengeMethod == "S256") {
                    // Invalid codeChallengeMethod
                    let errorResponse = createErrorResponse(request: request,
                                                            redirectURI: redirectURIString,
                                                            errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                                            errorDescription: "Invalid code challenge method",
                                                            state: state)
                    return (errorResponse, nil)
                }
            } else {
                // codeChallengeMethod is missing
                let errorResponse = createErrorResponse(request: request,
                                                        redirectURI: redirectURIString,
                                                        errorType: OAuthResponseParameters.ErrorType.invalidRequest,
                                                        errorDescription: "Code challenge method is required when code challenge is provided",
                                                        state: state)
                return (errorResponse, nil)
            }
        }
        
        // Extract nonce for OpenID Connect
        let nonce: String? = request.query[OAuthRequestParameters.nonce]
        
        
        let authRequestObject = AuthorizationGetRequestObject(clientID: clientID, redirectURIString: redirectURIString,
                                                              scopes: scopes, state: state,
                                                              responseType: responseType,
                                                              codeChallenge: codeChallenge,
                                                              codeChallengeMethod: codeChallengeMethod,
                                                              nonce: nonce)  // Include nonce in the request object
        
        return (nil, authRequestObject)
    }
    
    private func createErrorResponse(
        request: Request,
        redirectURI: String,
        errorType: String,
        errorDescription: String,
        state: String?
    ) -> Vapor.Response {
        var redirectString = "\(redirectURI)?error=\(errorType)&error_description=\(errorDescription)"
        
        if let state = state {
            redirectString += "&state=\(state)"
        }
        
        return request.redirect(to: redirectString)
    }
}

struct AuthorizationGetRequestObject {
    let clientID: String
    let redirectURIString: String
    let scopes: [String]
    let state: String?
    let responseType: String
    let codeChallenge: String?
    let codeChallengeMethod: String?
    let nonce: String?  // OpenID Connect specific
}
