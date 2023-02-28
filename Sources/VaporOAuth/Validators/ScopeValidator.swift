struct ScopeValidator {
    let validScopes: [String]?
    let clientRetriever: ClientRetriever

    func validateScope(clientID: String, scopes: [String]?) async throws {
        if let requestedScopes = scopes {
            let providerScopes = validScopes ?? []

            if !providerScopes.isEmpty {
                for scope in requestedScopes {
                    guard providerScopes.contains(scope) else {
                        throw ScopeError.unknown
                    }
                }
            }

            let client = try await clientRetriever.getClient(clientID: clientID)
            if let clientScopes = client?.validScopes {
                for scope in requestedScopes {
                    guard clientScopes.contains(scope) else {
                        throw ScopeError.invalid
                    }
                }
            }
        }
    }
}

public enum ScopeError: Error {
    case invalid
    case unknown
}
