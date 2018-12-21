# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.3] - 2018-12-21

### Changed

- Changed error messages thrown from the verify method. (From reversed sentences
  to normal sentences)

### Fixed

- Tokens was invalidated before they expired (in MemoryStore).

- Added missing descriptions for some options in `JWTManagerOptions`.

## [0.1.2] - 2018-12-19

### Fixed

- Include comments in package.

## [0.1.1] - 2018-11-02

### Added

- Added the decoded token to error handler when it is available.

### Changed

- Changed `JWTManager` from default export to named export.

- Made the argument for `JWTManager#invalidate` optional.

### Removed

- Removed intallation with tag 'latest' for GitHub in readme.

## 0.1.0 - 2018-11-01

### Added

- Initial release

[Unreleased]: https://github.com/revam/node-jwt-manager/compare/v0.1.3...HEAD
[0.1.3]: https://github.com/revam/node-jwt-manager/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/revam/node-jwt-manager/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/revam/node-jwt-manager/compare/v0.1.0...v0.1.1
