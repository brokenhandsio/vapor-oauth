public protocol ClientRetriever {
    func getClient(clientID: String) -> OAuthClient?
}
