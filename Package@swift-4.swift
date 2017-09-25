// swift-tools-version:4.0

import PackageDescription

let package = Package(
    name: "VaporOAuth",
    products: [
        .library(name: "VaporOAuth", targets: ["VaporOAuth"]),
    ],
    dependencies: [
    	.package(url: "https://github.com/vapor/vapor.git", .upToNextMajor(from: "2.2.0")),
        .package(url: "https://github.com/vapor/auth-provider.git", .upToNextMajor(from: "1.2.0")),
    ],
    targets: [
        .target(name: "VaporOAuth", dependencies: ["Vapor", "AuthProvider"]),
        .testTarget(name: "VaporOAuthTests", dependencies: ["VaporOAuth"]),
    ]
)
