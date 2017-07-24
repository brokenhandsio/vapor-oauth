public protocol UserManager {
    func authenticateUser(username: String, password: String) -> String?
    func getUser(id: String) -> OAuthUser?
}
