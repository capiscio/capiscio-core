# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.3.1] - 2025-01-14

### Fixed
- Aligned all version references across package metadata

## [2.3.0] - 2025-01-13

### Added
- **PoP Client (RFC-003)**: Badge issuance via Proof of Possession protocol for IAL-1 verification
- **Staleness Fail-Closed (RFC-002 v1.3 §7.5)**: Badges now fail validation when stale (fail-closed security posture)

### Fixed
- **Integration Tests**: Improved integration test fixtures and assertions
- **CI Workflow**: Exclude integration tests from release workflow to prevent false failures

### Documentation
- Comprehensive CLI documentation audit and fixes
- Added Copilot workspace guidelines

## [2.2.0] - 2025-12-10

### Changed
- **VERSION ALIGNMENT**: All CapiscIO packages now share the same version number.
  - `capiscio-core`, `capiscio` (npm), and `capiscio` (PyPI) are all v2.2.0.
  - Major version bump from 1.x to align with CLI wrappers.

### Added
- **Trust Badges (RFC-002)**: Full implementation of trust badge issuance and verification.
- **gRPC API**: BadgeService, ScoringService, and ValidationService via gRPC.
- **MkDocs Documentation**: Comprehensive API reference and user guides.

## [1.0.2] - 2025-11-20

### Fixed
- **Lint Issues**: Fixed golangci-lint warnings and updated configuration.
- **Test Coverage**: Improved test coverage to 70%+.

## [1.0.1] - 2025-11-15

### Fixed
- **Badge Verification**: Fixed self-signed badge verification edge cases.
- **Scoring**: Improved scoring algorithm for edge cases.

## [1.0.0] - 2025-11-10

### Added
- **Initial Release**: Core validation engine for A2A Agent Cards.
- **CLI Commands**: `validate`, `badge`, `key`, `gateway` commands.
- **Badge System**: Issue and verify trust badges with Ed25519 signatures.
- **Scoring Engine**: Multi-category scoring with weighted rubrics.
- **gRPC Server**: High-performance RPC interface.
