import VaporOAuth
import Node

class FakeUserManager: UserManager {
    var users: [OAuthUser] = []
    
    func authenticateUser(username: String, password: String) -> Identifier? {
        for user in users {
            if user.username == username {
                if user.password.makeString() == password {
                    return user.id
                }
            }
        }
        
        return nil
    }
    
    func getUser(userID: Identifier) -> OAuthUser? {
        for user in users {
            if user.id == userID {
                return user
            }
        }
        return nil
    }
}
