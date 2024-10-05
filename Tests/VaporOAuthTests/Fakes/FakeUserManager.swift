import VaporOAuth

class FakeUserManager: UserManager {
    var users: [OAuthUser] = []

    func authenticateUser(username: String, password: String) -> String? {
        for user in users where user.username == username {
            if user.password == password {
                return user.id
            }
        }

        return nil
    }

    func getUser(userID: String) -> OAuthUser? {
        for user in users where user.id == userID {
            return user
        }
        return nil
    }
}
