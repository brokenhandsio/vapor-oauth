public struct EmptyUserManager: UserManager {

    public init() {}

    public func getUser(userID: String) async throws -> OAuthUser? {
        return nil
    }

    public func authenticateUser(username: String, password: String) async throws -> String? {
        return nil
    }
}
