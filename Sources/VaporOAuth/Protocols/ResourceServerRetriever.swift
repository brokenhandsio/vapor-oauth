public protocol ResourceServerRetriever {
    func getServer(_ username: String) async throws -> OAuthResourceServer?
}
