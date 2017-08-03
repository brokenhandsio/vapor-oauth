import OAuth
import Node

struct StubUserManager: UserManager {
    func authenticateUser(username: String, password: String) -> Identifier? {
        return nil
    }
    
    func getUser(id: Identifier) -> OAuthUser? {
        return nil
    }
}
