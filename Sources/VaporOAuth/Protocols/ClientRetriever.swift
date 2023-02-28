public protocol ClientRetriever {
    func getClient(clientID: String) async throws -> OAuthClient?
}
