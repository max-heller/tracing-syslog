# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2024-01-20

### Added

- `Syslog::invalid_chars()` to allow configuring behavior when a message to be logged contains
  characters that are invalid in a C string (i.e., interior nul bytes) (#5)

### Changed

- If a log message contains characters that are invalid in a C string (i.e., interior nul bytes),
  these characters are replaced with the Unicode replacement character (�) and the modified message
  is logged to syslog. This is a change from the past default, which was to panic in debug mode and
  log a message in release mode. (#5)

## [0.2.0] - 2023-05-07

### Changed

- Disabled unused `tracing-subscriber` features (#1)
- Updated to Rust 2021 edition
- Updated `once_cell` to 1.17
