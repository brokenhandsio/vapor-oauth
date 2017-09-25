public enum OAuthFlowType: String {
    case authorization = "authorization_code"
    case implicit = "implicit"
    case password = "password"
    case clientCredentials = "client_credentials"
    case refresh = "refresh_token"
    case tokenIntrospection = "token_introspection"
}
