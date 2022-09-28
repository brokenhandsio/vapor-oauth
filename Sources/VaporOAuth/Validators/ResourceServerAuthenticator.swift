import Vapor

struct ResourceServerAuthenticator {

    let resourceServerRetriever: ResourceServerRetriever

    func authenticate(credentials: BasicAuthorization) throws {
        guard let resourceServer = resourceServerRetriever.getServer(credentials.username) else {
            throw Abort(.unauthorized)
        }

        guard resourceServer.password == credentials.password else {
            throw Abort(.unauthorized)
        }
    }
}
