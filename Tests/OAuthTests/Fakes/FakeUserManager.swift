import OAuth

class FakeUserManager: UserManager {
    var users: [OAuthUser] = []
    
    func authenticateUser(username: String, password: String) -> String? {
        for user in users {
            if user.username == username {
                if user.password.makeString() == password {
                    return user.userID
                }
            }
        }
        
        return nil
    }
    
    func getUser(id: String) -> OAuthUser? {
        for user in users {
            if user.userID == id {
                return user
            }
        }
        return nil
    }
}
