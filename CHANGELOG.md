# Changelog

All notable changes to Collect-LinuxMemoryDump will be documented in this file.

## [1.0.0] - 2026-10-12

Initial Release

### Added
- Linux Memory Acquisition w/ AVML (uncompressed LiME image) - no on-target compilation required
- Linux Memory Acquisition w/ LiME (uncompressed LiME image) - on-target compilation of the Loadable Kernel Module (LKM)
- Linux Memory Acquisition w/ MAGNET DumpIt for Linux (Linux ELF Core image) - no kernel module required
- Support for x86_64 and ARM64 (AVML also supports 32-bit ARM Big-Endian)
- Custom Output Directory (`--output-path`)
- Kernel Lockdown Check (acquisition is aborted if Kernel Lockdown is active)
- Safety Guardrail (memory dumps restricted to 256 GB or less)
- Disk Space Check before acquisition (Physical Memory + 12.5% Safety Margin)
- File Integrity Check of the AVML and DumpIt binaries (SHA256)
- MD5 Hash Calculation of the memory snapshot
- Password-protected 7-Zip archive incl. Archive Verification before cleaning up
- tar Fallback for architectures without 7-Zip (e.g. 32-bit ARM)
- Basic System Information Collection
- Mapping Layout Collection (System.map, Runtime Symbol Table incl. KASLR addresses, Kernel Banner, Kernel Config)
- Kernel Image Collection (vmlinuz, BTF Type Information and Debug Kernel w/ DWARF, if available)
- Screen Log (cleaned log file of the entire acquisition incl. duration)

### Bundled Tools
- 7-Zip v26.03
- AVML v0.20.0
- LiME v1.12.0
- MAGNET DumpIt for Linux v0.1.0
