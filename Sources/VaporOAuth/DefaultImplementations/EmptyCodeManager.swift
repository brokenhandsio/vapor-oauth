public struct EmptyCodeManager: CodeManager {
    public init() {}

    public func getCode(_ code: String) -> OAuthCode? {
        return nil
    }

    public func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?
    ) throws -> String {
        return ""
    }

    public func codeUsed(_ code: OAuthCode) {}
}
