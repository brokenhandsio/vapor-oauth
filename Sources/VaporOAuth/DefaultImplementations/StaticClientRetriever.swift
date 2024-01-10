public struct StaticClientRetriever: ClientRetriever {
    private let clients: [String: OAuthClient]
    
    public init(clients: [OAuthClient]) {
        self.clients = clients.reduce(into: [String: OAuthClient]()) { (dict, client) in
            dict[client.clientID] = client
        }
    }
    
    public func getClient(clientID: String) throws -> OAuthClient? {
        return clients[clientID]
    }
}
