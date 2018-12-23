# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.5] - 2018-12-23

### Added

- A new method `decode` to decode tokens into javascript objects without
  verifying first. Be careful when using.

### Fixed

- Not all thrown errors from methods of `JWTManager` was handled by the
  `onError` method of the manager.

## [0.1.4] - 2018-12-22

### Changed

- Interface `JWT` has now no required types, all optional.

- Function `FindSubjectFunction` now accepts an object with subject and
  additional properties as return type.

- Function `FunctionVerify` now accepts value `undefined` as return type.

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

[Unreleased]: https://github.com/revam/node-jwt-manager/compare/v0.1.5...HEAD
[0.1.5]: https://github.com/revam/node-jwt-manager/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/revam/node-jwt-manager/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/revam/node-jwt-manager/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/revam/node-jwt-manager/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/revam/node-jwt-manager/compare/v0.1.0...v0.1.1
