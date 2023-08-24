import Vapor

struct ClientValidator {

    let clientRetriever: ClientRetriever
    let scopeValidator: ScopeValidator
    let environment: Environment

    func validateClient(clientID: String, responseType: String, redirectURI: String, scopes: [String]?) async throws {
        guard let client = try await clientRetriever.getClient(clientID: clientID) else {
            throw AuthorizationError.invalidClientID
        }

        if client.confidentialClient ?? false {
            guard responseType == ResponseType.code else {
                throw AuthorizationError.confidentialClientTokenGrant
            }
        }

        guard client.validateRedirectURI(redirectURI) else {
            throw AuthorizationError.invalidRedirectURI
        }

        if responseType == ResponseType.code {
            guard client.allowedGrantType == .authorization else {
                throw Abort(.forbidden)
            }
        } else {
            guard client.allowedGrantType == .implicit else {
                throw Abort(.forbidden)
            }
        }

        try await scopeValidator.validateScope(clientID: clientID, scopes: scopes)

        let redirectURI = URI(stringLiteral: redirectURI)

        if environment == .production {
            if redirectURI.scheme != "https" {
                throw AuthorizationError.httpRedirectURI
            }
        }
    }

    func authenticateClient(clientID: String, clientSecret: String?, grantType: OAuthFlowType?,
                            checkConfidentialClient: Bool = false) async throws {
        guard let client = try await clientRetriever.getClient(clientID: clientID) else {
            throw ClientError.unauthorized
        }

        guard clientSecret == client.clientSecret else {
            throw ClientError.unauthorized
        }

        if let grantType = grantType {
            guard client.allowedGrantType == grantType else {
                throw Abort(.forbidden)
            }

            if grantType == .password {
                guard client.firstParty else {
                    throw ClientError.notFirstParty
                }
            }
            
            if grantType == .deviceCode {
                
            }
        }

        if checkConfidentialClient {
            guard client.confidentialClient ?? false else {
                throw ClientError.notConfidential
            }
        }
    }
}

public enum ClientError: Error {
    case unauthorized
    case notFirstParty
    case notConfidential
}
