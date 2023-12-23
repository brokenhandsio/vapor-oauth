import Vapor

public final class OAuthDiscoveryDocument: Content {
    public let issuer: String
    public let authorizationEndpoint: String
    public let tokenEndpoint: String
    public let userInfoEndpoint: String
    public let revocationEndpoint: String
    public let introspectionEndpoint: String
    public let jwksURI: String
    public let registrationEndpoint: String
    public let scopesSupported: [String]
    public let responseTypesSupported: [String]
    public let grantTypesSupported: [String]
    public let tokenEndpointAuthMethodsSupported: [String]
    public let tokenEndpointAuthSigningAlgValuesSupported: [String]
    public let serviceDocumentation: String
    public let uiLocalesSupported: [String]
    public let opPolicyURI: String
    public let opTosURI: String

    public var extend: [String: Any] = [:]

    public init(
        issuer: String,
        authorizationEndpoint: String,
        tokenEndpoint: String,
        userInfoEndpoint: String,
        revocationEndpoint: String,
        introspectionEndpoint: String,
        jwksURI: String,
        registrationEndpoint: String,
        scopesSupported: [String],
        responseTypesSupported: [String],
        grantTypesSupported: [String],
        tokenEndpointAuthMethodsSupported: [String],
        tokenEndpointAuthSigningAlgValuesSupported: [String],
        serviceDocumentation: String,
        uiLocalesSupported: [String],
        opPolicyURI: String,
        opTosURI: String
    ) {
        self.issuer = issuer
        self.authorizationEndpoint = authorizationEndpoint
        self.tokenEndpoint = tokenEndpoint
        self.userInfoEndpoint = userInfoEndpoint
        self.revocationEndpoint = revocationEndpoint
        self.introspectionEndpoint = introspectionEndpoint
        self.jwksURI = jwksURI
        self.registrationEndpoint = registrationEndpoint
        self.scopesSupported = scopesSupported
        self.responseTypesSupported = responseTypesSupported
        self.grantTypesSupported = grantTypesSupported
        self.tokenEndpointAuthMethodsSupported = tokenEndpointAuthMethodsSupported
        self.tokenEndpointAuthSigningAlgValuesSupported = tokenEndpointAuthSigningAlgValuesSupported
        self.serviceDocumentation = serviceDocumentation
        self.uiLocalesSupported = uiLocalesSupported
        self.opPolicyURI = opPolicyURI
        self.opTosURI = opTosURI
    }

    // Exclude 'extend' property from encoding
    private enum CodingKeys: String, CodingKey {
        case issuer
        case authorizationEndpoint
        case tokenEndpoint
        case userInfoEndpoint
        case revocationEndpoint
        case introspectionEndpoint
        case jwksURI
        case registrationEndpoint
        case scopesSupported
        case responseTypesSupported
        case grantTypesSupported
        case tokenEndpointAuthMethodsSupported
        case tokenEndpointAuthSigningAlgValuesSupported
        case serviceDocumentation
        case uiLocalesSupported
        case opPolicyURI
        case opTosURI
    }
}
