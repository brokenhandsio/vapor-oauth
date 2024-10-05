import VaporOAuth

struct StubUserManager: UserManager {
    func authenticateUser(username: String, password: String) -> String? {
        nil
    }

    func getUser(userID: String) -> OAuthUser? {
        nil
    }
}
