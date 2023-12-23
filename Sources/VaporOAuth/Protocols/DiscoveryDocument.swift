import Foundation

public protocol DiscoveryDocument: Sendable {
    var issuer: String { get }
    var authorizationEndpoint: String { get }
    var tokenEndpoint: String { get }
    var userInfoEndpoint: String { get }
    var revocationEndpoint: String { get }
    var introspectionEndpoint: String { get }
    var jwksURI: String { get }
    var registrationEndpoint: String { get }
    var scopesSupported: [String] { get }
    var responseTypesSupported: [String] { get }
    var grantTypesSupported: [String] { get }
    var tokenEndpointAuthMethodsSupported: [String] { get }
    var tokenEndpointAuthSigningAlgValuesSupported: [String] { get }
    var serviceDocumentation: String { get }
    var uiLocalesSupported: [String] { get }
    var opPolicyURI: String { get }
    var opTosURI: String { get }
    var extend: [String: Any] { get set }
    var resourceServerRetriever: ResourceServerRetriever? { get }
}
