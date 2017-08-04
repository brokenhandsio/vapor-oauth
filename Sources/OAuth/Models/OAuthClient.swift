import Core

public final class OAuthClient: Extendable {

    public let clientID: String
    public let redirectURIs: [String]?
    public let clientSecret: String?
    public let validScopes: [String]?
    public let confidentialClient: Bool?
    public let firstParty: Bool
    public let allowedGrantTypes: [OAuthFlowType]?

    public var extend: [String: Any] = [:]

    public init(clientID: String, redirectURIs: [String]?, clientSecret: String? = nil, validScopes: [String]? = nil, confidential: Bool? = nil, firstParty: Bool = false, allowedGrantTypes: [OAuthFlowType]? = nil) {
        self.clientID = clientID
        self.redirectURIs = redirectURIs
        self.clientSecret = clientSecret
        self.validScopes = validScopes
        self.confidentialClient = confidential
        self.firstParty = firstParty
        self.allowedGrantTypes = allowedGrantTypes
    }

    func validateRedirectURI(_ redirectURI: String) -> Bool {
        guard let redirectURIs = redirectURIs else {
            return false
        }

        if (redirectURIs.contains(redirectURI)) {
            return true
        }

        return false
    }

}
