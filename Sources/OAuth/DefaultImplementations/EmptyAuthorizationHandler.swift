import HTTP
import URI

public struct EmptyAuthorizationHandler: AuthorizeHandler {
    public init() {}

    public func handleAuthorizationError(_ errorType: AuthorizationError) throws -> ResponseRepresentable {
        return ""
    }

    public func handleAuthorizationRequest(_ request: Request, responseType: String, clientID: String,
                                           redirectURI: URI, scope: [String], state: String?,
                                           csrfToken: String) throws -> ResponseRepresentable {
        return ""
    }
}
