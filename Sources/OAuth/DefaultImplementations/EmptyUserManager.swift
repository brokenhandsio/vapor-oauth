public struct EmptyUserManager: UserManager {
    
    public init() {}
    
    public func getUser(id: String) -> OAuthUser? {
        return nil
    }
    
    public func authenticateUser(username: String, password: String) -> String? {
        return nil
    }
}
