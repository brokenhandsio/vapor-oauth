import OAuth

struct StubUserManager: UserManager {
    func authenticateUser(username: String, password: String) -> String? {
        return nil
    }
    
    func getUser(id: String) -> OAuthUser? {
        return nil
    }
}
