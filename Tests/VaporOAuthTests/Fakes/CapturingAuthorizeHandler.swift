import VaporOAuth
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
    
    func handleAuthorizationRequest(_ request: Request, authorizationRequestObject: AuthorizationRequestObject) throws -> ResponseRepresentable {
        self.request = request
        self.responseType = authorizationRequestObject.responseType
        self.clientID = authorizationRequestObject.clientID
        self.redirectURI = authorizationRequestObject.redirectURI
        self.scope = authorizationRequestObject.scope
        self.state = authorizationRequestObject.state
        self.csrfToken = authorizationRequestObject.csrfToken
        
        return "Allow/Deny"
    }
    
    private(set) var authorizationError: AuthorizationError?
    func handleAuthorizationError(_ errorType: AuthorizationError) -> ResponseRepresentable {
        authorizationError = errorType
        return "Error"
    }
}
