# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-10-03

### Added
- Initial release of cordra-python library
- Support for both REST API and DOIP API
- Complete authentication system (password, JWT, private key)
- Comprehensive error handling with detailed exceptions
- Full type hints and documentation
- Support for all Cordra operations:
  - Object CRUD operations
  - Advanced search with facets and filtering
  - Type method invocation
  - Batch operations (DOIP only)
  - Version management (DOIP only)
  - Relationship queries (DOIP only)
  - Access control management
  - Password management

### Features
- **Dual API Support**: Choose between REST API or DOIP API based on needs
- **Authentication**: Password, JWT bearer, and private key authentication
- **Type Safety**: Complete type annotations for better IDE support
- **Error Handling**: Detailed exception hierarchy for different error types
- **Documentation**: Comprehensive README with examples and API reference

### Compatibility
- **Cordra Version**: Tested on Cordra 2.5.2
- **Python Versions**: 3.7+ (3.7, 3.8, 3.9, 3.10, 3.11, 3.12)
- **Dependencies**: Only `requests>=2.25.0`

### Documentation
- Complete API documentation with parameter references
- Usage examples for all major features
- Error handling guide with status code mapping
- Installation and setup instructions

## [Unreleased]

### Added
- Initial development and testing

### Contributors
- Royal Institute for Cultural Heritage (KIK-IRPA)

---

## Template for Future Releases

### [X.Y.Z] - YYYY-MM-DD

### Added
- New features

### Changed
- Changes to existing functionality

### Deprecated
- Features marked for removal in future versions

### Removed
- Removed features

### Fixed
- Bug fixes

### Security
- Security-related fixes
