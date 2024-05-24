# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- ...
### Changed
- update documentation
### Deprecated
- ...
### Removed
- ...
### Fixed
- ...
### Security:
- ...

## [0.1.1] - 2019-02-08
### Added
- Specify `readme` in Cargo.toml

## [0.1.0] - 2019-02-01
### Added
- `DecodeBE`, `DecodeLe`, `DecodeME` - for creating structs from bytes stored as big, little or mixed endianess.
- `EncodeBE`, `EncodeLe`, `EncodeME` - for change structures into bytes stored as big, little or mixed endianess.
- `endian` attribute for `DecodeME` and `EncodeME`
- derive crate (`endian_codec_derive`) available via future `derive` enabled by default


[Unreleased]: https://github.com/xoac/endian_codec/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/xoac/endian_codec/releases/tag/v0.1.1
[0.1.0]: https://github.com/xoac/endian_codec/releases/tag/v0.1.0
