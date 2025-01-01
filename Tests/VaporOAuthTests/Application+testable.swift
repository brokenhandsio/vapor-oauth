import XCTVapor

@testable import VaporOAuth

extension Application {
    static func testableWithTester() throws -> (Application, XCTApplicationTester) {
        let app = Application(.testing)
        do {
            let tester = try app.testable()
            return (app, tester)
        } catch {
            app.shutdown()
            throw error
        }
    }

    static func testable() throws -> Application {
        let (app, _) = try self.testableWithTester()
        return app
    }
}
