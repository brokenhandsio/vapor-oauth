import Logging

class CapturingLogger: LogHandler {
    static var shared: CapturingLogger = CapturingLogger()

    subscript(metadataKey key: String) -> Logging.Logger.Metadata.Value? {
        get { metadata[key] }
        set(newValue) { metadata[key] = newValue }
    }

    var metadata: Logging.Logger.Metadata = [:]
    var logLevel: Logging.Logger.Level = .trace
    private(set) var logMessage: String?

    func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        logLevel = level
        logMessage = "\(message)"
    }
}
