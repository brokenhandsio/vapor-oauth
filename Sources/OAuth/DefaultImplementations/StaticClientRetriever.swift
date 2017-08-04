public struct StaticClientRetriever: ClientRetriever {

    let clients: [String: OAuthClient]

    public init(clients: [OAuthClient]) {
        self.clients = clients.reduce([String: OAuthClient]()) { (dict, client) -> [String: OAuthClient] in
            var dict = dict
            dict[client.clientID] = client
            return dict
        }
    }

    public func getClient(clientID: String) -> OAuthClient? {
        return clients[clientID]
    }
}
