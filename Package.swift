// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "VaporOAuth",
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
        )
    ]
)
