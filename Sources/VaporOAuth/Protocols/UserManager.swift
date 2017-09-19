import Node

public protocol UserManager {
    func authenticateUser(username: String, password: String) -> Identifier?
    func getUser(userID: Identifier) -> OAuthUser?
}
