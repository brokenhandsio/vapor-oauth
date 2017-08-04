import HTTP
import URI

public protocol AuthorizeHandler {
    func handleAuthorizationRequest(_ request: Request, responseType: String, clientID: String, redirectURI: URI,
                                    scope: [String], state: String?, csrfToken: String) throws -> ResponseRepresentable
    func handleAuthorizationError(_ errorType: AuthorizationError) throws -> ResponseRepresentable
}

public enum AuthorizationError: Error {
    case invalidClientID
    case confidentialClientTokenGrant
    case invalidRedirectURI
    case httpRedirectURI
}
