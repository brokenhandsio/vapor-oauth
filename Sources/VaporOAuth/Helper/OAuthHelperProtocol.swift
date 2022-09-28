protocol OAuthHelperProtocol {
    func assertScopes(_ scopes: [String]?) async throws
    func user() async throws -> OAuthUser
}
