import Vapor

extension HTTPHeaders {
    public struct Location: ExpressibleByStringLiteral, Equatable {
        public let value: String

        public init(value: String) {
            self.value = value
        }

        public init(stringLiteral value: String) {
            self.init(value: value)
        }
    }

    public var location: Location? {
        get {
            self.first(name: .location).flatMap(Location.init(value:))
        }
        set {
            if let value = newValue {
                self.replaceOrAdd(name: .location, value: value.value)
            } else {
                self.remove(name: .location)
            }
        }
    }
}
