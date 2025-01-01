import VaporOAuth

class FakeUserManager: UserManager {
    var users: [OAuthUser] = []

    func authenticateUser(username: String, password: String) -> String? {
        for user in users {
            if user.username == username {
                if user.password == password {
                    return user.id
                }
            }
        }

        return nil
    }

    func getUser(userID: String) -> OAuthUser? {
        for user in users {
            if user.id == userID {
                return user
            }
        }
        return nil
    }
}
