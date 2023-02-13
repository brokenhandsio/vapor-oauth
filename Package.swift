// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "vapor-oauth",
    platforms: [
        .macOS(.v12)
    ],
    products: [
        .library(
            name: "OAuth",
            targets: ["VaporOAuth"]
        )
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.0.0")
    ],
    targets: [
        .target(
            name: "VaporOAuth",
            dependencies: [.product(name: "Vapor", package: "vapor")]
        ),
        .testTarget(name: "VaporOAuthTests", dependencies: [
            .target(name: "VaporOAuth"),
            .product(name: "XCTVapor", package: "vapor")
        ])
    ]
)
