import Vapor

public struct EmptyAuthorizationHandler: AuthorizeHandler {
    public init() {}

    public func handleAuthorizationRequest(
        _ request: Request,
        authorizationRequestObject: AuthorizationRequestObject
    ) async throws -> Response {
        Response(body: "")
    }

    public func handleAuthorizationError(_ errorType: AuthorizationError) async throws -> Response {
        Response(body: "")
    }
}
