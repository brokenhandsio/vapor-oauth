import HTTP
import JSON

struct TokenIntrospectionHandler {
    func handleRequest(_ req: Request) throws -> ResponseRepresentable {
        var json = JSON()
        
        guard let token = req.data["token"]?.string else {
            try json.set("error", "missing_token")
            try json.set("error_description", "The token parameter is required")
            let response = Response(status: .badRequest)
            response.json = json
            return response
        }
        
        return "OK"
    }
}
