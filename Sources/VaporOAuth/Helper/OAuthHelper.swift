protocol OAuthHelper {
    func assertScopes(_ scopes: [String]?) throws
    func user() throws -> OAuthUser
}
