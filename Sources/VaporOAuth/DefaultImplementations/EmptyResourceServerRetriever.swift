public struct EmptyResourceServerRetriever: ResourceServerRetriever {

    public init() {}

    public func getServer(_ username: String) async throws -> OAuthResourceServer? {
        return nil
    }
}
