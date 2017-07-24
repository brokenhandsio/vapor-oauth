public enum ScopeError: Error {
    case invalid
    case unknown
}

public enum ClientError: Error {
    case unauthorized
    case notFirstParty
    case notConfidential
}
