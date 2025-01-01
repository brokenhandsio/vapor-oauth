import VaporOAuth

class StubCodeManager: CodeManager {

    var codeToReturn = "ABCDEFHIJKLMNO"

    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?) throws -> String {
        return codeToReturn
    }

    func getCode(_ code: String) -> OAuthCode? {
        return nil
    }

    func codeUsed(_ code: OAuthCode) {

    }
}
