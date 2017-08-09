import HTTP
import JSON

struct TokenIntrospectionHandler {
    
    let clientValidator: ClientValidator
    
    func handleRequest(_ req: Request) throws -> ResponseRepresentable {
        
        guard let clientID = req.data[OAuthRequestParameters.clientID]?.string else {
            return try createErrorResponse(status: .badRequest, errorMessage: OAuthResponseParameters.ErrorType.invalidRequest, errorDescription: "Request was missing the 'client_id' parameter")
        }
        
        guard let clientSecret = req.data[OAuthRequestParameters.clientSecret]?.string else {
            return try createErrorResponse(status: .badRequest, errorMessage: OAuthResponseParameters.ErrorType.invalidRequest, errorDescription: "Request was missing the 'client_secret' parameter")
        }
        
        do {
            try clientValidator.authenticateClient(clientID: clientID,
                                                   clientSecret: clientSecret,
                                                   grantType: .tokenIntrospection)
        } catch {
            return try createErrorResponse(status: .unauthorized, errorMessage: OAuthResponseParameters.ErrorType.invalidClient,
                                           errorDescription: "Request had invalid client credentials")
        }
        
        guard let token = req.data[OAuthRequestParameters.token]?.string else {
            return try createErrorResponse(status: .badRequest, errorMessage: OAuthResponseParameters.ErrorType.missingToken, errorDescription: "The token parameter is required")
        }
        
        return "OK"
    }
    
    func createErrorResponse(status: Status, errorMessage: String, errorDescription: String) throws -> Response {
        var json = JSON()
        try json.set(OAuthResponseParameters.error, errorMessage)
        try json.set(OAuthResponseParameters.errorDescription, errorDescription)
        let response = Response(status: status)
        response.json = json
        return response
    }
}
