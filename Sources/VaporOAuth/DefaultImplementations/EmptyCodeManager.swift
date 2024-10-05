public struct EmptyCodeManager: CodeManager {
    public init() {}

    public func getCode(_ code: String) -> OAuthCode? {
        nil
    }

    public func generateCode(
        userID: String,
        clientID: String,
        redirectURI: String,
        scopes: [String]?
    ) throws -> String {
        ""
    }

    public func codeUsed(_ code: OAuthCode) {}
}
