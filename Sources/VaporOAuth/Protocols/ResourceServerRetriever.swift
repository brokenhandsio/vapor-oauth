public protocol ResourceServerRetriever {
    func getServer(_ username: String) -> OAuthResourceServer?
}
