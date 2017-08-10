import OAuth

class FakeResourceServerRetriever: ResourceServerRetriever {
    
    var resourceServers: [String: OAuthResourceServer] = [:]
    
    func getServer(_ username: String) -> OAuthResourceServer? {
        return resourceServers[username]
    }
}
