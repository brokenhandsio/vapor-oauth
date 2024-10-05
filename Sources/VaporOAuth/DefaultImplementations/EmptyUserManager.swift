public struct EmptyUserManager: UserManager {

    public init() {}

    public func getUser(userID: String) async throws -> OAuthUser? {
        nil
    }

    public func authenticateUser(username: String, password: String) async throws -> String? {
        nil
    }
}
