public struct EmptyResourceServerRetriever: ResourceServerRetriever {

    public init() {}

    public func getServer(_ username: String) -> OAuthResourceServer? {
        return nil
    }
}
