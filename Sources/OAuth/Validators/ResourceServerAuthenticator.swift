import Authentication
import Vapor

struct ResourceServerAuthenticator {

    let resourceServerRetriever: ResourceServerRetriever

    func authenticate(credentials: Password) throws {
        guard let resourceServer = resourceServerRetriever.getServer(credentials.username) else {
            throw Abort.unauthorized
        }

        guard try OAuthResourceServer.passwordVerifier.verify(password: credentials.password.makeBytes(),
                                                              matches: resourceServer.password) else {
            throw Abort.unauthorized
        }
    }
}
