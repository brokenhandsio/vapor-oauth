import VaporOAuth
import Node

struct StubUserManager: UserManager {
    func authenticateUser(username: String, password: String) -> Identifier? {
        return nil
    }
    
    func getUser(userID: Identifier) -> OAuthUser? {
        return nil
    }
}
