# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2019-02-14

### Changed

- Redefined and renamed interface `JWTIdStore`, which stores ALL valid JWT
  identifiers, to a new iterface `JWTAuthority`, which keeps track of all
  invalid JWT identifiers untill their Time-To-Live (ttl) expires.

  Because the verify function first checks if the token is expired before
  checking if the id is valid. So it is more efficent to track all
  invalidated-but-not-expired token identifiers instead of keeping track of all
  valid identifiers.

  Also property `storage` in manager options has been replaced by `authority`.

- Merged content from "types.ts" and "memory-store.ts" into main.ts. The
  in-memory authority does not need to be exported, as it will only be used by
  the manager, if at all. And the options and function types has been moved into
  the managers namespace.
  (e.g. `JWTManagerOptions` -> `JWTManager.Options`,
  `JWTGenerateOptions` -> `JWTManager.GenerateOptions`, and
  `FindSubjectFunction` -> `JWTManager.FindSubjectFunction`)

- `JWTManager.VerifyFunction` (renamed from `VerifySubjectFunction`) now
  provides the JWT-token for verification, and not just the token subject. Use
  it as you see fit.

- Updated scripts and configuration for project. Transpiled sources has no
  comments, but transpiled declaraions has comments.

### Removed

- Removed exports `MemoryStore` and `pick`. Create your own or use one from
  another library.

## [0.2.2] - 2018-12-26

### Added

- Added a new export class `Signal`.
  (Signal provider may be replaced by a package in a future release.)

- Added basic signals `onGenerate`, `onVerify`, `onInvalidate` and `onError`.

### Changed

- The `verifyHeader` method now accepts an audience instead of schema. The
  schema it verifies is now hard-coded, and the audience is passed on to the
  `verify` method.

- All non-fatal errors are now properly handed over to the `onError` signal.

### Removed

- Removed `onError` field from constructor options (`JWTManagerOptions`).
  Users should register listeners to the `onError` signal on the manager
  instance instead.

## [0.2.1] - 2018-12-25

### Added

- A new function type `GenerateIDFunction`.

### Changed

- Token ID generation is now supplied to the constructor, and should always
  be unique.

- Updated package description.

### Removed

- Removed package "uuid" as a peer-dependency.

## [0.2.0] - 2018-12-24

### Added

- Added a new type `JWTGenerateOptions`.

### Changed

- Renamed `add` to `generate` to better describe what it does. And changed its
  signature to (only) accept options of type `JWTGenerateOptions`.

- Allow alternate audience when verifying by providing an additional argument to
  the method.

- Made `verify`, `verifyHeader` and `decode` accept `undefined` as a value for
  token/header.

- Updated _some_ examples in readme.

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

[Unreleased]: https://github.com/revam/node-jwt-manager/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/revam/node-jwt-manager/compare/v0.2.2...v0.3.0
[0.2.2]: https://github.com/revam/node-jwt-manager/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/revam/node-jwt-manager/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/revam/node-jwt-manager/compare/v0.1.5...v0.2.0
[0.1.5]: https://github.com/revam/node-jwt-manager/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/revam/node-jwt-manager/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/revam/node-jwt-manager/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/revam/node-jwt-manager/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/revam/node-jwt-manager/compare/v0.1.0...v0.1.1
