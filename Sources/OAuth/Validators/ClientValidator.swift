import Vapor

struct ClientValidator {

    let clientRetriever: ClientRetriever
    let scopeValidator: ScopeValidator
    let environment: Environment

    func validateClient(clientID: String, responseType: String, redirectURI: String, scopes: [String]?) throws {
        guard let client = clientRetriever.getClient(clientID: clientID) else {
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
            guard client.allowedGrantTypes?.contains(.authorization) ?? true else {
                throw Abort(.forbidden)
            }
        } else {
            guard client.allowedGrantTypes?.contains(.implicit) ?? true else {
                throw Abort(.forbidden)
            }
        }

        try scopeValidator.validateScope(clientID: clientID, scopes: scopes)

        let redirectURI = URIParser.shared.parse(bytes: redirectURI.makeBytes())

        if environment == .production {
            if redirectURI.scheme != "https" {
                throw AuthorizationError.httpRedirectURI
            }
        }
    }
}

public enum ClientError: Error {
    case unauthorized
    case notFirstParty
    case notConfidential
}
