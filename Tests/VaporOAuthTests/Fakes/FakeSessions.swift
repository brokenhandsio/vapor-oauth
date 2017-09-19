import Sessions

class FakeSessions: SessionsProtocol {
    
    var sessions: [String: Session] = [:]
    
    /// Creates a new, random identifier
    /// to use for storing a Session
    func makeIdentifier() throws -> String {
        return "ID"
    }
    
    /// Loads a session for the given identifier--
    /// if one exists.
    func get(identifier: String) throws -> Session? {
        return sessions[identifier]
    }
    
    /// Stores the session, using its identifier.
    func set(_ session: Session) throws {
    }
    
    /// Destroys the session associated with the identifier
    func destroy(identifier: String) throws {
    }
    
    /// Returns true if a session with this identifier exists
    func contains(identifier: String) throws -> Bool {
        return sessions[identifier] != nil
    }
}
