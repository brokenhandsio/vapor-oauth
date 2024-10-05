/// Responsible for generating and managing OAuth Codes.
public protocol CodeManager {

    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?) async throws -> String
    func getCode(_ code: String) async throws -> OAuthCode?

    // This is explicit to ensure that the code is marked as used or deleted (it could be implied that this is done when you call
    // `getCode` but it is called explicitly to remind developers to ensure that codes can't be reused)
    func codeUsed(_ code: OAuthCode) async throws

}
