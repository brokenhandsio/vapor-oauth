import Vapor

public final class OAuthClient: Extendable, Sendable {
    public let clientID: String
    public let redirectURIs: [String]?
    public let clientSecret: String?
    public let validScopes: [String]?
    public let confidentialClient: Bool?
    public let firstParty: Bool
    public let allowedGrantType: OAuthFlowType

    // OpenID Connect specific properties
    public let postLogoutRedirectURIs: [String]?
    public let idTokenSignedResponseAlg: String? // Algorithm for signing ID tokens

    public var extend: Vapor.Extend = .init()

    public init(clientID: String, redirectURIs: [String]?, clientSecret: String? = nil, validScopes: [String]? = nil,
                confidential: Bool? = nil, firstParty: Bool = false, allowedGrantType: OAuthFlowType,
                postLogoutRedirectURIs: [String]? = nil, idTokenSignedResponseAlg: String? = "RS256") {
        self.clientID = clientID
        self.redirectURIs = redirectURIs
        self.clientSecret = clientSecret
        self.validScopes = validScopes
        self.confidentialClient = confidential
        self.firstParty = firstParty
        self.allowedGrantType = allowedGrantType
        self.postLogoutRedirectURIs = postLogoutRedirectURIs
        self.idTokenSignedResponseAlg = idTokenSignedResponseAlg
    }

    func validateRedirectURI(_ redirectURI: String) -> Bool {
        guard let redirectURIs = redirectURIs else {
            return false
        }

        return redirectURIs.contains(redirectURI)
    }

    // Additional validation for post-logout redirect URIs
    func validatePostLogoutRedirectURI(_ redirectURI: String) -> Bool {
        guard let postLogoutRedirectURIs = postLogoutRedirectURIs else {
            return false
        }

        return postLogoutRedirectURIs.contains(redirectURI)
    }
}
