public protocol ResourceServerRetriever: Sendable {
    func getServer(_ username: String) async throws -> OAuthResourceServer?
}
