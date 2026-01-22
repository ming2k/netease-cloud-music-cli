# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2025-01-22

### Added
- Initial release
- Search songs by keyword
- Download songs with quality selection (standard to master quality)
- Download entire playlists and albums
- Get song lyrics with translation support
- Cookie-based authentication for VIP features
- Daily recommendations (requires login)
- New releases discovery by region
- Standalone binary support via PyInstaller
- GitHub Actions release workflow for multi-platform builds

### Features
- Multiple audio quality levels: standard, higher, exhigh, lossless, hires, jyeffect, sky, jymaster
- VIP song detection with graceful fallback
- Rich CLI interface with progress bars
- Custom filename templates
- XDG Base Directory support for config storage
