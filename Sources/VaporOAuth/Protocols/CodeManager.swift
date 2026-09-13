/// Responsible for generating and managing OAuth Codes
public protocol CodeManager {
    func generateCode(userID: String, clientID: String, redirectURI: String, scopes: [String]?) async throws -> String

    /// Generates a code, optionally recording the PKCE (RFC 7636) `code_challenge`/`code_challenge_method`
    /// supplied at the authorize step so they can be verified against the `code_verifier` sent to the
    /// token endpoint.
    ///
    /// A default implementation is provided that forwards to the four-argument overload and discards
    /// the challenge, so existing conformances keep compiling. If you want PKCE to actually be enforced,
    /// you MUST override this overload yourself and persist `codeChallenge`/`codeChallengeMethod` on the
    /// `OAuthCode` you store — otherwise the challenge is silently dropped and PKCE verification at the
    /// token endpoint will be skipped for every code you issue.
    func generateCode(
        userID: String, clientID: String, redirectURI: String, scopes: [String]?,
        codeChallenge: String?, codeChallengeMethod: String?
    ) async throws -> String

    func getCode(_ code: String) async throws -> OAuthCode?

    // This is explicit to ensure that the code is marked as used or deleted (it could be implied that this is done when you call
    // `getCode` but it is called explicitly to remind developers to ensure that codes can't be reused)
    func codeUsed(_ code: OAuthCode) async throws
}

extension CodeManager {
    public func generateCode(
        userID: String, clientID: String, redirectURI: String, scopes: [String]?,
        codeChallenge: String?, codeChallengeMethod: String?
    ) async throws -> String {
        try await generateCode(userID: userID, clientID: clientID, redirectURI: redirectURI, scopes: scopes)
    }
}
