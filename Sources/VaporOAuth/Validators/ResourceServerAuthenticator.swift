import Vapor

struct ResourceServerAuthenticator {

    let resourceServerRetriever: ResourceServerRetriever

    func authenticate(credentials: BasicAuthorization) async throws {
        guard let resourceServer = try await resourceServerRetriever.getServer(credentials.username) else {
            throw Abort(.unauthorized)
        }

        guard resourceServer.password == credentials.password else {
            throw Abort(.unauthorized)
        }
    }
}
