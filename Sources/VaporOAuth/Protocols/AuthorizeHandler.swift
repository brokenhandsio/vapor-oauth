import Vapor

public protocol AuthorizeHandler: Sendable {
    func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response
    
    func handleAuthorizationError(_ errorType: AuthorizationError) async throws -> Response
}

public enum AuthorizationError: Error {
    case invalidClientID
    case confidentialClientTokenGrant
    case invalidRedirectURI
    case httpRedirectURI
    // OpenID Connect specific errors
    case invalidScope
    case invalidNonce
    case invalidRequest
    case unauthorizedClient
    case accessDenied
    case unsupportedResponseType
    case invalidGrant
    case serverError
    case temporarilyUnavailable
    // Other potential errors
    case invalidRequestObject
    case requestNotSupported
    case requestUriNotSupported
    case registrationNotSupported
}


public struct AuthorizationRequestObject {
    public let responseType: String
    public let clientID: String
    public let redirectURI: URI
    public let scope: [String]
    public let state: String?
    public let csrfToken: String
    // PKCE parameters
    public let codeChallenge: String?
    public let codeChallengeMethod: String?
    // OpenID Connect specific parameters
    public let nonce: String?
    
    public init(responseType: String, clientID: String, redirectURI: URI, scope: [String], state: String?, csrfToken: String, codeChallenge: String?, codeChallengeMethod: String?, nonce: String?) {
        self.responseType = responseType
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scope = scope
        self.state = state
        self.csrfToken = csrfToken
        self.codeChallenge = codeChallenge
        self.codeChallengeMethod = codeChallengeMethod
        self.nonce = nonce
    }
}
