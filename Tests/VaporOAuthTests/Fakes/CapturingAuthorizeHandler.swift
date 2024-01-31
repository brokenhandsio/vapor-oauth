import VaporOAuth
import Vapor

class CapturingAuthoriseHandler: AuthorizeHandler {
    private(set) var request: Request?
    private(set) var responseType: String?
    private(set) var clientID: String?
    private(set) var redirectURI: URI?
    private(set) var scope: [String]?
    private(set) var state: String?
    private(set) var csrfToken: String?
    // Add PKCE parameters
    private(set) var codeChallenge: String?
    private(set) var codeChallengeMethod: String?
    
    func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response {
        self.request = request
        self.responseType = authorizationRequestObject.responseType
        self.clientID = authorizationRequestObject.clientID
        self.redirectURI = authorizationRequestObject.redirectURI
        self.scope = authorizationRequestObject.scope
        self.state = authorizationRequestObject.state
        self.csrfToken = authorizationRequestObject.csrfToken
        // Capture PKCE parameters
        self.codeChallenge = authorizationRequestObject.codeChallenge
        self.codeChallengeMethod = authorizationRequestObject.codeChallengeMethod
        return Response(body: .init(string: "Allow/Deny"))
    }
    
    private(set) var authorizationError: AuthorizationError?
    func handleAuthorizationError(_ errorType: AuthorizationError) async throws -> Response {
        authorizationError = errorType
        return Response(body: .init(string: "Error"))
    }
}
