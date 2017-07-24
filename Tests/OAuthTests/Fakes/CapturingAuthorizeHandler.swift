import OAuth
import HTTP
import URI

class CapturingAuthoriseHandler: AuthorizeHandler {
    private(set) var request: Request?
    private(set) var responseType: String?
    private(set) var clientID: String?
    private(set) var redirectURI: URI?
    private(set) var scope: [String]?
    private(set) var state: String?
    private(set) var csrfToken: String?
    
    func handleAuthorizationRequest(_ request: Request, responseType: String, clientID: String, redirectURI: URI, scope: [String], state: String?, csrfToken: String) -> ResponseRepresentable {
        self.request = request
        self.responseType = responseType
        self.clientID = clientID
        self.redirectURI = redirectURI
        self.scope = scope
        self.state = state
        self.csrfToken = csrfToken
        
        return "Allow/Deny"
    }
    
    private(set) var authorizationError: AuthorizationError?
    func handleAuthorizationError(_ errorType: AuthorizationError) -> ResponseRepresentable {
        authorizationError = errorType
        return "Error"
    }
}
