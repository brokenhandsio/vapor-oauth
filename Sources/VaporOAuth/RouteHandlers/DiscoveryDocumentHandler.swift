import Vapor

struct DiscoveryDocumentHandler {
    
    let discoveryDocument: DiscoveryDocument  // Accept a DiscoveryDocument conforming object
    
    init(discoveryDocument: DiscoveryDocument) {
        self.discoveryDocument = discoveryDocument
    }
    
    
    func generateDiscoveryDocument() -> OAuthDiscoveryDocument {
        // Access properties and methods from the provided discoveryDocument
        let issuer = discoveryDocument.issuer
        let authorizationEndpoint = discoveryDocument.authorizationEndpoint
        let tokenEndpoint = discoveryDocument.tokenEndpoint
        let userInfoEndpoint = discoveryDocument.userInfoEndpoint
        let revocationEndpoint = discoveryDocument.revocationEndpoint
        let introspectionEndpoint = discoveryDocument.introspectionEndpoint
        let jwksURI = discoveryDocument.jwksURI
        let registrationEndpoint = discoveryDocument.registrationEndpoint
        let scopesSupported = discoveryDocument.scopesSupported
        let responseTypesSupported = discoveryDocument.responseTypesSupported
        let grantTypesSupported = discoveryDocument.grantTypesSupported
        let tokenEndpointAuthMethodsSupported = discoveryDocument.tokenEndpointAuthMethodsSupported
        let tokenEndpointAuthSigningAlgValuesSupported = discoveryDocument.tokenEndpointAuthSigningAlgValuesSupported
        let serviceDocumentation = discoveryDocument.serviceDocumentation
        let uiLocalesSupported = discoveryDocument.uiLocalesSupported
        let opPolicyURI = discoveryDocument.opPolicyURI
        let opTosURI = discoveryDocument.opTosURI
        
        // Create an OAuthDiscoveryDocument object
        let discoveryDocument = OAuthDiscoveryDocument(
            issuer: issuer,
            authorizationEndpoint: authorizationEndpoint,
            tokenEndpoint: tokenEndpoint,
            userInfoEndpoint: userInfoEndpoint,
            revocationEndpoint: revocationEndpoint,
            introspectionEndpoint: introspectionEndpoint,
            jwksURI: jwksURI,
            registrationEndpoint: registrationEndpoint,
            scopesSupported: scopesSupported,
            responseTypesSupported: responseTypesSupported,
            grantTypesSupported: grantTypesSupported,
            tokenEndpointAuthMethodsSupported: tokenEndpointAuthMethodsSupported,
            tokenEndpointAuthSigningAlgValuesSupported: tokenEndpointAuthSigningAlgValuesSupported,
            serviceDocumentation: serviceDocumentation,
            uiLocalesSupported: uiLocalesSupported,
            opPolicyURI: opPolicyURI,
            opTosURI: opTosURI
        )
        
        // Return the generated discovery document
        return discoveryDocument
        
    }
    
    func handleRequest(request: Request) throws -> OAuthDiscoveryDocument {
        // Generate and return the OAuth 2.0 Discovery Document
        return generateDiscoveryDocument()
    }
}
