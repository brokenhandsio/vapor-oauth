import OAuth

class FakeClientGetter: ClientRetriever {
    
    var validClients: [String: OAuthClient] = [:]
    
    func getClient(clientID: String) -> OAuthClient? {
        return validClients[clientID]
    }
}
