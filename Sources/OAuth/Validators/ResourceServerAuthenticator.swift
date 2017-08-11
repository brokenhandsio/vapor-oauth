import Authentication
import Vapor

struct ResourceServerAuthenticator {

    let resourceServerRetriever: ResourceServerRetriever

    func authenticate(credentials: Password) throws {
        guard let resourceServer = resourceServerRetriever.getServer(credentials.username) else {
            throw Abort.unauthorized
        }

        guard resourceServer.password.makeString() == credentials.password else {
            throw Abort.unauthorized
        }
    }
}
