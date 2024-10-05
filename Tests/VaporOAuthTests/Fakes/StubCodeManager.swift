import VaporOAuth

class StubCodeManager: CodeManager {

    var codeToReturn = "ABCDEFHIJKLMNO"

    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?) throws -> String {
        codeToReturn
    }

    func getCode(_ code: String) -> OAuthCode? {
        nil
    }

    func codeUsed(_ code: OAuthCode) {

    }
}
