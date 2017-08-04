import HTTP
import URI

public protocol AuthorizeHandler {
    func handleAuthorizationRequest(_ request: Request,
                                    authorizationRequestObject: AuthorizationRequestObject) throws -> ResponseRepresentable
    func handleAuthorizationError(_ errorType: AuthorizationError) throws -> ResponseRepresentable
}

public enum AuthorizationError: Error {
    case invalidClientID
    case confidentialClientTokenGrant
    case invalidRedirectURI
    case httpRedirectURI
}

public struct AuthorizationRequestObject {
    public let responseType: String
    public let clientID: String
    public let redirectURI: URI
    public let scope: [String]
    public let state: String?
    public let csrfToken: String
}
