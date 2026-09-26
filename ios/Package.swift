// swiftlint:disable all

import PackageDescription

let package = Package(
    name: "TransferDaemon",
    platforms: [
        .iOS(.v16)
    ],
    products: [
        .library(
            name: "TransferDaemon",
            targets: ["TransferDaemon"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "TransferDaemon",
            dependencies: [
                .target(name: "transferd_mobile")
            ],
            resources: []
        ),
        .binaryTarget(
            name: "transferd_mobile",
            path: "transferd_mobile.xcframework"
        ),
    ]
)
