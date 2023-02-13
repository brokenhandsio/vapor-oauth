public struct EmptyUserManager: UserManager {

    public init() {}

    public func getUser(userID: String) -> OAuthUser? {
        return nil
    }

    public func authenticateUser(username: String, password: String) -> String? {
        return nil
    }
}
