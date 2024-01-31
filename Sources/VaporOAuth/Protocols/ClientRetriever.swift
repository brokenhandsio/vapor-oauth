public protocol ClientRetriever: Sendable {
    func getClient(clientID: String) async throws -> OAuthClient?
}
