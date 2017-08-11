struct OAuthRequestParameters {
    static let clientID = "client_id"
    static let clientSecret = "client_secret"
    static let redirectURI = "redirect_uri"
    static let responseType = "response_type"
    static let scope = "scope"
    static let state = "state"
    static let applicationAuthorized = "applicationAuthorized"
    static let grantType = "grant_type"
    static let refreshToken = "refresh_token"
    static let code = "code"
    static let password = "password"
    static let usernname = "username"
    static let csrfToken = "csrfToken"
    static let token = "token"
}

struct OAuthResponseParameters {

    static let error = "error"
    static let errorDescription = "error_description"
    static let tokenType = "token_type"
    static let expires = "expires_in"
    static let accessToken = "access_token"
    static let refreshToken = "refresh_token"
    static let scope = "scope"
    static let active = "active"
    static let clientID = "client_id"
    static let username = "username"
    static let expiry = "exp"

    struct ErrorType {
        static let invalidRequest = "invalid_request"
        static let invalidScope = "invalid_scope"
        static let invalidClient = "invalid_client"
        static let unauthorizedClient = "unauthorized_client"
        static let unsupportedGrant = "unsupported_grant_type"
        static let invalidGrant = "invalid_grant"
        static let missingToken = "missing_token"
    }
}

struct ResponseType {
    static let code = "code"
    static let token = "token"
}

struct SessionData {
    static let csrfToken = "CSRFToken"
}
