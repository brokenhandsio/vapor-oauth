import Vapor

public struct OAuthHelper: Sendable {
    public var assertScopes: @Sendable ([String]?, Request) async throws -> Void
    public var user: @Sendable (Request) async throws -> OAuthUser

    public init(
        assertScopes: @escaping @Sendable ([String]?, Request) async throws -> Void,
        user: @escaping @Sendable (Request) async throws  -> OAuthUser
    ) {
        self.assertScopes = assertScopes
        self.user = user
    }
}

extension Application {
    struct OAuthHelperKey: StorageKey {
        typealias Value = OAuthHelper
    }

    public var oAuthHelper: OAuthHelper {
        get {
            guard let oAuthHelper = storage[OAuthHelperKey.self] else {
                fatalError("OAuthHelperKey not set up. Use app.oAuthHelper = ...")
            }
            return oAuthHelper
        }
        set {
            storage[OAuthHelperKey.self] = newValue
        }
    }
}

extension Request {
    public var oAuthHelper: OAuthHelper { application.oAuthHelper }
}

extension Request {
    func getOAuthToken() throws -> String {
        guard let authHeader = headers.first(name: .authorization) else {
            throw Abort(.forbidden)
        }

        guard authHeader.lowercased().hasPrefix("bearer ") else {
            throw Abort(.forbidden)
        }

        let token = String(authHeader[authHeader.index(authHeader.startIndex, offsetBy: 7)...])

        guard !token.isEmpty else {
            throw Abort(.forbidden)
        }

        return token
    }
}
