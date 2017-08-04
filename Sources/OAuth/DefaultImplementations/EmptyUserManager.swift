import Node

public struct EmptyUserManager: UserManager {

    public init() {}

    public func getUser(id: Identifier) -> OAuthUser? {
        return nil
    }

    public func authenticateUser(username: String, password: String) -> Identifier? {
        return nil
    }
}
