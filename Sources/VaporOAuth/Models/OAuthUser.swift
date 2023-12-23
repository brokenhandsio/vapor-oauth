import Vapor

public final class OAuthUser: Authenticatable, Extendable, Encodable {
    public let username: String
    public let emailAddress: String?
    public var password: String

    public var id: String?

    // OpenID Connect specific attributes
    public var name: String?
    public var givenName: String?
    public var familyName: String?
    public var middleName: String?
    public var nickname: String?
    public var profile: String?
    public var picture: String?
    public var website: String?
    public var gender: String?
    public var birthdate: String?
    public var zoneinfo: String?
    public var locale: String?
    public var phoneNumber: String?
    public var updatedAt: Date?

    public var extend: Extend = .init()

    public init(userID: String? = nil, username: String, emailAddress: String?, password: String,
                name: String? = nil, givenName: String? = nil, familyName: String? = nil, middleName: String? = nil,
                nickname: String? = nil, profile: String? = nil, picture: String? = nil, website: String? = nil,
                gender: String? = nil, birthdate: String? = nil, zoneinfo: String? = nil, locale: String? = nil,
                phoneNumber: String? = nil, updatedAt: Date? = nil) {
        self.username = username
        self.emailAddress = emailAddress
        self.password = password
        self.id = userID
        self.name = name
        self.givenName = givenName
        self.familyName = familyName
        self.middleName = middleName
        self.nickname = nickname
        self.profile = profile
        self.picture = picture
        self.website = website
        self.gender = gender
        self.birthdate = birthdate
        self.zoneinfo = zoneinfo
        self.locale = locale
        self.phoneNumber = phoneNumber
        self.updatedAt = updatedAt
    }
}
