# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [0.5.0] - 2025-06-23
### Fixed
- Ensure hosts with changed IPs are re-scanned and updated in the database.


## [0.4.0] - 2025-06-23
### Added
- Added LICENSE file.
- Pre-commit was set up with some basic rules.

### Changed
- Minor issues were fixed to comply with flake, PEP8, etc.

## [0.3.0] - 2025-06-19
### Added
- `status` field to track host online/offline in real-time.
- Host details view with full change history.
- Footer and navigation enhancements with icons.

### Changed
- Replaced all `print()` statements with proper `logging`.
- Updated authentication to require login for all views.
- Compact login form UI.

### Fixed
- Circular import issue during app init.
- Hosts incorrectly marked as offline due to missing status update.

## [0.2.0] - 2025-06-17
### Added
- Initial web UI using Flask and Bootstrap 5.
- Persistent scan history and open port tracking.
- SQLite storage of host metadata and scan results.
- Login system with hardcoded users.

## [0.1.0] - 2025-06-15
### Added
- First working version of Nmap-based scanner.
- Parsing of MAC/IP/Hostname/Vendor/OS/Ports from XML.
