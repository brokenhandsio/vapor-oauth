import Vapor

struct FakeSessions: SessionDriver {
    var sessions: [SessionID: SessionData] = [:]

    func createSession(_ data: SessionData, for request: Request) -> EventLoopFuture<SessionID> {
        return request.eventLoop.makeSucceededFuture(.init(string: ""))
    }

    func readSession(_ sessionID: SessionID, for request: Request) -> EventLoopFuture<SessionData?> {
        return request.eventLoop.makeSucceededFuture(sessions[sessionID])
    }

    func updateSession(_ sessionID: SessionID, to data: SessionData, for request: Request) -> EventLoopFuture<SessionID> {
        return request.eventLoop.makeSucceededFuture(.init(string: ""))
    }

    func deleteSession(_ sessionID: SessionID, for request: Request) -> EventLoopFuture<Void> {
        return request.eventLoop.makeSucceededFuture(())
    }

}
