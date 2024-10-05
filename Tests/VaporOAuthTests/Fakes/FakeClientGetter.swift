import VaporOAuth

class FakeClientGetter: ClientRetriever {

    var validClients: [String: OAuthClient] = [:]

    func getClient(clientID: String) async throws -> OAuthClient? {
        validClients[clientID]
    }
}
