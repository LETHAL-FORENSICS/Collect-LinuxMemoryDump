#!/bin/bash
#
# Collect-LinuxMemoryDump v1.0.0
#
# @author:    Martin Willing
# @copyright: 2026 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2026-10-07
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# README
# Collect-LinuxMemoryDump - Linux Memory Acquisition for Digital Forensics and Incident Response (DFIR)
#
# Usage:
# sudo bash ./Collect-LinuxMemoryDump.sh [OPTION] [--output-path PATH]
#
# Help:
# sudo bash ./Collect-LinuxMemoryDump.sh -h
#
# Example 1:
# sudo bash ./Collect-LinuxMemoryDump.sh  --avml
#
# Collect Linux Memory Acquisition w/ AVML (uncompressed LiME image)
#
# Example 2:
# sudo bash ./Collect-LinuxMemoryDump.sh  --lime
#
# Collect Linux Memory Acquisition w/ LiME (uncompressed LiME image)
#
# Note: LiME does NOT support spaces in file paths (script location and output path). Rename the folder/volume if necessary (e.g. 'T7 Shield' -> 'T7_Shield').
#
# Example 3:
# sudo bash ./Collect-LinuxMemoryDump.sh  --dumpit
#
# Collect Linux Memory Acquisition w/ MAGNET DumpIt for Linux (Linux ELF Core image)
#
#
# Dependencies:
#
# 7-Zip v26.03 (2026-09-03)
# https://www.7-zip.org/download.html
#
# AVML v0.20.0 (2026-07-09)
# https://github.com/microsoft/avml/
#
# LiME v1.12.0 (2026-03-31)
# https://github.com/jtsylve/LiME
#
# MAGNET DumpIt for Linux v0.1.0 (2023-11-21)
# https://github.com/MagnetForensics/dumpit-linux
#
#
#############################################################################################################################################################################################

# Hash Values

# 7zz (x86-64)             MD5: FA74FE0E4256805D2A18A756E3BAA9A5   SHA1: 1E6FCE082A1DC28B06843E391D6EF2F5D295ADF3   SHA256: 3D52C92DEB7E9F1BD059692EEFC33F86A144CDC548ACC4B6F4C809A4DD7BC369
# 7zz (arm64)              MD5: A77CC8920434EF4BC0C70DEA5E50A1AA   SHA1: EE2A8FFF67AE07810542491B12DD5AED58D79364   SHA256: 9A26E7D54BFDAE8A8F1750CDB70697547B738C2334AA89F3D3F2C8645C8443FE
# avml                     MD5: 70A9CEF21DB1B4DD41683E73CAB43DA7   SHA1: FCC0E3F6960969E0BE8C7BF876DF34BA8340F3CD   SHA256: A67010B08AF2EDF5A04D2F051A133E0D8E30853C308F055B8335E759609D6DC9
# avml-aarch64             MD5: 9519844E28D04BBED38DE28696FE09D4   SHA1: 11E7B4FFA712B5DC3DA5D3F921B1402994E112BE   SHA256: D3FA9285E94AD4268CB7ED20A62D8BD7B1AC4561E191B8A82654864B4541B3AD 
# avml-armv6b              MD5: 179D78BA514F9445B4B6294E2F46D825   SHA1: B5D964D3B2D7C5434F8C928AF583BD98A755ADA3   SHA256: 8C05B89D5FF6393E6673C9999AF96BD2091A67E6D31EE79062DE51E3DA54FC23
# dumpitforlinux-x86_64    MD5: CBEF07F64A6B78DEAC26A96A3F90B948   SHA1: 76F20CB77CF798394BC34EA1B1FCC657F829D22C   SHA256: EEF3F1289784DC37F3ED268263A51C11A33EEC9B7158063215D0BABC44F9D3C5
# dumpitforlinux-aarch64   MD5: 3BDCC9ADF4D3143350BEE0E7DB0F4107   SHA1: E23D2EE609975C5C92F693DF1D5947233DC7E155   SHA256: 1A3795D5D9A84B43DC08031D061896DBA88D23BC5E8ECDF3070A743E0269BAB2

#############################################################################################################################################################################################

# Declarations
SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
TIMESTAMP=$(date -u '+%FT%H%M%S') # YYYY-MM-DDThhmmss (UTC)
BASE_DIR="$SCRIPT_DIR/output"
HOST_NAME=$(uname -n)
HOST_NAME="${HOST_NAME%%.*}"
ARCHIVE_PASSWORD="IncidentResponse"
OUTPUT_PATH=""
MODE=""

# Colors
RED=$'\e[91m'
YELLOW=$'\e[93m'
RESET=$'\e[0m'

START_TIME=$SECONDS

#############################################################################################################################################################################################

VERSION="v1.0.0"
SCRIPT_NAME="$(basename "$0")"

Header()
{
echo "Collect-LinuxMemoryDump $VERSION - Linux Memory Acquisition for Digital Forensics and Incident Response (DFIR)"
echo "(c) 2026 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
echo ""

/bin/cat << "EOF"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
EOF

echo ""
}

Usage()
{
echo "Usage: $SCRIPT_NAME [OPTION] [--output-path PATH]"
echo ""
echo "Options:"
echo "-a / --avml        Memory Acquisition w/ AVML (uncompressed LiME image)"
echo "-d / --dumpit      Memory Acquisition w/ MAGNET DumpIt for Linux (Linux ELF Core image)"
echo "-l / --lime        Memory Acquisition w/ LiME (uncompressed LiME image)"
echo "-h / --help        Show this help message"
echo ""
echo "Optional Second Argument:"
echo "--output-path     Specify Custom Output Directory (Default: $SCRIPT_DIR/output)"
echo ""
echo "Note: LiME does NOT support spaces in file paths."
echo ""
exit "${1:-0}"
}

#############################################################################################################################################################################################

AVML()
{

# AVML (Acquire Volatile Memory for Linux) - A portable volatile memory acquisition tool for Linux (x86_64)
# Note: AVML can be used to acquire memory without knowing the target OS distribution or kernel a priori. No on-target compilation or fingerprinting is needed.

# avml - This is the default static binary compiled for standard x86_64 (64-bit Intel/AMD) Linux environments.
# avml-aarch64 - This version is cross-compiled for ARM64 (64-bit ARM) architectures.
# avml-armv6b - This version is compiled for legacy or embedded 32-bit ARM architectures utilizing Big-Endian byte ordering.

# Check if the script is being run as root
if [[ $EUID -ne 0 ]]; then
	echo "[Error] This script must be run as root." 1>&2
	echo ""
	exit 1
fi

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Create Output Directories
mkdir -p "$OUTPUT_DIR/SystemInfo"
mkdir -p "$OUTPUT_DIR/Memory"

# Kernel Lockdown
LOCKDOWN_FILE="/sys/kernel/security/lockdown"

if [ -r "$LOCKDOWN_FILE" ]; then
  KERNEL_LOCKDOWN=$(grep -o '\[[a-z]*\]' "$LOCKDOWN_FILE" | tr -d '[]')
  echo "$KERNEL_LOCKDOWN" > "$OUTPUT_DIR"/SystemInfo/Kernel-Lockdown.txt
  if [ "$KERNEL_LOCKDOWN" != "none" ]; then
    echo "[Error] Kernel Lockdown is ACTIVE. Memory Acquisition is NOT possible." 1>&2
    echo "" 1>&2
    exit 1
  fi
else
  echo "[Info]  Kernel Lockdown: not available (not supported by kernel)"
fi

# Processor Architecture (Kernel)
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    AVML="$SCRIPT_DIR/Tools/AVML/avml"
    AVML_SHA256="A67010B08AF2EDF5A04D2F051A133E0D8E30853C308F055B8335E759609D6DC9"
    SEVENZIP="$SCRIPT_DIR/Tools/7-Zip/x86-64/7zz"
    ;;
  aarch64|arm64)
    AVML="$SCRIPT_DIR/Tools/AVML/avml-aarch64"
    AVML_SHA256="D3FA9285E94AD4268CB7ED20A62D8BD7B1AC4561E191B8A82654864B4541B3AD"
    SEVENZIP="$SCRIPT_DIR/Tools/7-Zip/arm64/7zz"
    ;;
  armv*b|armeb)
    AVML="$SCRIPT_DIR/Tools/AVML/avml-armv6b"
    AVML_SHA256="8C05B89D5FF6393E6673C9999AF96BD2091A67E6D31EE79062DE51E3DA54FC23"
    ;;
  *)
    echo "[Error] Unsupported Processor Architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Short Hostname
echo "[Info]  Host Name: $HOST_NAME"

# Total Physical Memory Size
RAM_MB=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
if [ -z "$RAM_MB" ] || [ "$RAM_MB" -eq 0 ]; then
  echo "[Error] Could not determine Total Physical Memory Size." 1>&2
  echo "" 1>&2
  exit 1
fi
RAM_GB=$(awk -v mb="$RAM_MB" 'BEGIN {printf "%.1f", mb / 1024}')
echo "[Info]  Total Physical Memory Size: $RAM_GB GB"

# Check if the binary exists (AVML)
if [ ! -f "$AVML" ]; then
  echo "[Error] AVML binary not found: $AVML" >&2
  exit 1
fi

# Verify File Integrity (AVML)
HASH=$(sha256sum "$AVML" | awk '{print toupper($1)}')
if [ "$HASH" = "$AVML_SHA256" ]; then
  echo "[Info]  File Integrity (AVML): OK"
else
  echo "${RED}[ALERT] File Integrity (AVML): FAILURE${RESET}" 1>&2
  echo "" 1>&2
  exit 1
fi

# Check if the binary can be executed (AVML)
if [ ! -x "$AVML" ]; then
  chmod +x "$AVML" 2>/dev/null || { echo "[Error] $AVML is not executable." >&2; exit 1; }
fi

# Safety Guardrail (restrict volatile memory dumps to 256 GB or less)
# Note: Prevents severe disk exhaustion, excessive memory smearing, OOM crashes and kernel panics on systems with more than 256 GB of memory.
MAX_MEMORY_MB=262144 # 256 GB (256 * 1024 MB)
if (( RAM_MB > MAX_MEMORY_MB )); then
  echo "[Error] Total System Memory ($RAM_GB GB) exceeds the limit of 256 GB." 1>&2
  echo "" 1>&2
  exit 1
fi

# Required Disk Space (Physical Memory + 12.5% Safety Margin)
REQUIRED_MB=$(( RAM_MB + RAM_MB / 8 ))

# Check Available Disk Space
AVAILABLE_MB=$(df -Pm "$OUTPUT_DIR" | awk 'NR==2 {print $4}')
if (( AVAILABLE_MB < REQUIRED_MB )); then
	echo "[Error] Not enough disk space to save memory dump file." 1>&2
	echo "[Error] Required: $REQUIRED_MB MB, Available: $AVAILABLE_MB MB" 1>&2
	echo "" 1>&2
	exit 1
fi

# Memory Acquisition (uncompressed LiME image)
MEMORY_DUMP="$OUTPUT_DIR"/Memory/AVML/"$HOST_NAME"_AVML.lime
ERROR_LOG="$OUTPUT_DIR"/Memory/AVML/AVML-Error.txt
echo "[Info]  Creating Memory Snapshot w/ AVML [approx. 1-5 min.] ... "
mkdir -p "$OUTPUT_DIR/Memory/AVML"
"$AVML" acquire "$MEMORY_DUMP" 2> "$ERROR_LOG"
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ] && [ -s "$MEMORY_DUMP" ]; then
	# Remove Error Log (if empty)
	[ -s "$ERROR_LOG" ] || rm -f "$ERROR_LOG"
else
	echo "[Error] Memory Acquisition failed (Exit Code: $EXIT_CODE). See AVML-Error.txt" 1>&2
	echo "" 1>&2
	exit 1
fi

# MD5 Calculation
DUMP_DIR="$OUTPUT_DIR/Memory/AVML"
DUMP_NAME="${HOST_NAME}_AVML.lime"
ARCHIVE_NAME="${HOST_NAME}_AVML.7z"
FILE="$DUMP_DIR/$DUMP_NAME"
if [ -f "$FILE" ]; then
  echo "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 1-5 min.] ... "
  MD5=$(md5sum "$FILE" | awk '{print toupper($1)}')
  echo "$MD5" > "$DUMP_DIR/MD5.txt"
  echo "[Info]  MD5 Hash: $MD5"

  # Compressing Memory Snapshot
  if [ -f "$SEVENZIP" ]; then
    echo "[Info]  Compressing Memory Snapshot [time-consuming-task] [approx. 10-60 min.] ... "
    if ( cd "$DUMP_DIR" \
         && "$SEVENZIP" a -t7z -mx5 -mhe=on -p"$ARCHIVE_PASSWORD" "$ARCHIVE_NAME" "$DUMP_NAME" MD5.txt \
         && "$SEVENZIP" t -p"$ARCHIVE_PASSWORD" "$ARCHIVE_NAME" ) > "$DUMP_DIR/7-Zip.txt" 2>&1; then
      echo "[Info]  Archive Name: $ARCHIVE_NAME"

      # Cleaning up (only after successful verification)
      rm -f "$FILE" "$DUMP_DIR/MD5.txt" "$DUMP_DIR/7-Zip.txt"
    else
      echo "[Error] Archive creation or verification failed. Memory Snapshot was NOT deleted. See 7-Zip.txt" 1>&2
    fi
  else
    # Fallback for architectures without 7-Zip (e.g. 32-bit ARM) --> NO encryption
    ARCHIVE_NAME="${HOST_NAME}_AVML.tar.gz"
    echo "[Info]  Compressing Memory Snapshot w/ tar [time-consuming-task] [approx. 10-60 min.] ... "
    if tar -czf "$DUMP_DIR/$ARCHIVE_NAME" -C "$DUMP_DIR" "$DUMP_NAME" MD5.txt > "$DUMP_DIR/tar.txt" 2>&1 \
       && tar -tzf "$DUMP_DIR/$ARCHIVE_NAME" > /dev/null 2>> "$DUMP_DIR/tar.txt"; then
      echo "[Info]  Archive Name: $ARCHIVE_NAME"
      echo "${YELLOW}[Warning] Archive is NOT encrypted (7-Zip NOT available for $ARCH).${RESET}" 1>&2

      # Cleaning up (only after successful verification)
      rm -f "$FILE" "$DUMP_DIR/MD5.txt" "$DUMP_DIR/tar.txt"
    else
      echo "[Error] Archive creation or verification failed. Memory Snapshot was NOT deleted. See tar.txt" 1>&2
    fi
  fi
fi

# Archive Size
FILE="$DUMP_DIR/$ARCHIVE_NAME"
if [ -f "$FILE" ]; then
  BYTES=$(stat -c %s "$FILE")
  FILESIZE=$(echo "$BYTES" | awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
  echo "[Info]  Archive Size: $FILESIZE"

  # Create Time
  EPOCH=$(stat -c %W "$FILE" 2>/dev/null)
  if [ -n "$EPOCH" ] && [ "$EPOCH" != "0" ] && [ "$EPOCH" != "?" ]; then
    BIRTH=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S')
    echo "[Info]  Create Time: $BIRTH UTC"
  else
    echo "[Info]  Create Time: not available (not supported by file system)"
  fi

  # Last Modified Time
  EPOCH=$(stat -c %Y "$FILE")
  MODIFY=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S')
  echo "[Info]  Last Modified Time: $MODIFY UTC"
fi

# AVML Version
AVML_VERSION=$("$AVML" -V | awk '{print $2}')
echo "$AVML_VERSION" > "$OUTPUT_DIR"/Memory/AVML-Version.txt

# Check latest version of AVML
API_URL="https://api.github.com/repos/microsoft/avml/releases/latest"
JSON=""

if command -v wget > /dev/null 2>&1; then
	JSON=$(wget -q -T 10 -t 1 -O - "$API_URL")
elif command -v curl > /dev/null 2>&1; then
	JSON=$(curl -s -m 10 "$API_URL")
fi

LATEST=$(echo "$JSON" | grep -o '"tag_name": *"[^"]*"' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+')

if [ -n "$LATEST" ]; then
	echo "$LATEST" > "$OUTPUT_DIR/Memory/AVML-Latest.txt"
else
	echo "[Info]  Could not determine latest AVML version (no internet connection, or wget/curl missing)." 1>&2
fi

# Basic System Information
echo "[Info]  Collecting Basic System Information ... "

# Hostname
cat /etc/hostname > "$OUTPUT_DIR"/SystemInfo/Hostname.txt
command -v hostnamectl > /dev/null && hostnamectl > "$OUTPUT_DIR"/SystemInfo/hostnamectl.txt 2> /dev/null

# OS Release Information
cat /etc/os-release > "$OUTPUT_DIR"/SystemInfo/OS-Release.txt

if [ -f /etc/centos-release ]; then
	cat /etc/centos-release > "$OUTPUT_DIR"/SystemInfo/CentOS-Release.txt 2> /dev/null
fi

if [ -f /etc/redhat-release ]; then
	cat /etc/redhat-release > "$OUTPUT_DIR"/SystemInfo/RedHat-Release.txt 2> /dev/null
fi

# System Uptime
uptime > "$OUTPUT_DIR"/SystemInfo/uptime.txt 2> /dev/null

if [ -f "$OUTPUT_DIR"/SystemInfo/OS-Release.txt ] && grep -q "Ubuntu" "$OUTPUT_DIR"/SystemInfo/OS-Release.txt; then
	uptime -p > "$OUTPUT_DIR"/SystemInfo/uptime-pretty.txt 2> /dev/null
	uptime -s > "$OUTPUT_DIR"/SystemInfo/uptime-since.txt 2> /dev/null
fi

# Timezone Information
command -v timedatectl > /dev/null && timedatectl > "$OUTPUT_DIR"/SystemInfo/timedatectl.txt 2> /dev/null

if [ -f /etc/timezone ]; then
	cat /etc/timezone > "$OUTPUT_DIR"/SystemInfo/Timezone.txt 2> /dev/null
fi

# Machine Hardware Name
MACHINE=$(uname -m)
echo "$MACHINE" > "$OUTPUT_DIR"/SystemInfo/Machine-Hardware-Name.txt

# Kernel Release
KERNEL_RELEASE=$(uname -r)
echo "$KERNEL_RELEASE" > "$OUTPUT_DIR"/SystemInfo/Kernel-Release.txt

# Kernel Name
KERNEL_NAME=$(uname -s)
echo "$KERNEL_NAME" > "$OUTPUT_DIR"/SystemInfo/Kernel-Name.txt

# Linux Profile Name
PRETTY_NAME=$(. /etc/os-release && echo "$PRETTY_NAME")
echo "[Info]  $PRETTY_NAME $MACHINE ($KERNEL_RELEASE)"

# Mapping Layout
KVER=$(uname -r)
MAPPING_DIR="$OUTPUT_DIR/Memory/Mapping-Layout"
echo "[Info]  Collecting Mapping Layout ... "
mkdir -p "$MAPPING_DIR"

# Collecting System.map (Static Symbol File)
if [ -r "/boot/System.map-$KVER" ]; then
	cp -p "/boot/System.map-$KVER" "$MAPPING_DIR/"
else
	echo "[Warning] /boot/System.map-$KVER NOT found." 1>&2
fi

# Collecting Kernel Symbols at Runtime (incl. KASLR addresses)
KALLSYMS="$MAPPING_DIR/kallsyms.txt"
cat /proc/kallsyms > "$KALLSYMS"

# Addresses are hidden only if ALL lines start with zeros
if ! grep -q -v '^0\+ ' "$KALLSYMS"; then
  KPTR_RESTRICT=$(cat /proc/sys/kernel/kptr_restrict)
  echo "[Info]  kallsyms addresses are hidden (kernel.kptr_restrict=$KPTR_RESTRICT). Temporarily disabling restriction ..."

  # Disable Kernel Pointer Restriction, dump kallsyms (this can act as your System.map replacement), restore original value immediately
  echo 0 > /proc/sys/kernel/kptr_restrict
  cat /proc/kallsyms > "$KALLSYMS"
  echo "$KPTR_RESTRICT" > /proc/sys/kernel/kptr_restrict
  echo "[Info]  kernel.kptr_restrict restored to $KPTR_RESTRICT."

  if ! grep -q -v '^0\+ ' "$KALLSYMS"; then
    echo "[Warning] kallsyms addresses are still hidden." 1>&2
  fi
fi

# Kernel Banner (Volatility 3 matches symbol tables by this banner)
cat /proc/version > "$MAPPING_DIR/version.txt"
uname -a > "$MAPPING_DIR/uname.txt"

# Kernel Config & Distribution
[ -r "/boot/config-$KVER" ] && cp -p "/boot/config-$KVER" "$MAPPING_DIR/"
[ -r /etc/os-release ] && cp -p /etc/os-release "$MAPPING_DIR/os-release.txt"

# Collecting Kernel Image (compressed, extract offline w/ extract-vmlinux)
# https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
KVER=$(uname -r)
KERNEL_DIR="$OUTPUT_DIR/Memory/Kernel-Image"
echo "[Info]  Collecting Kernel Image ..."
mkdir -p "$KERNEL_DIR"
if [ -r "/boot/vmlinuz-$KVER" ]; then
  cp -p "/boot/vmlinuz-$KVER" "$KERNEL_DIR/"
else
  # Fallback: Boot image from kernel command line (set by GRUB)
  BOOT_IMAGE=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^BOOT_IMAGE=//p')
  BOOT_IMAGE="${BOOT_IMAGE#\(*\)}" # strip GRUB device prefix, e.g. (hd0,gpt2)
  if [ -n "$BOOT_IMAGE" ] && [ -r "$BOOT_IMAGE" ]; then
    cp -p "$BOOT_IMAGE" "$KERNEL_DIR/"
  elif [ -n "$BOOT_IMAGE" ] && [ -r "/boot$BOOT_IMAGE" ]; then
    cp -p "/boot$BOOT_IMAGE" "$KERNEL_DIR/"
  else
    echo "[Error] Kernel image NOT found." 1>&2
  fi
fi

# BTF Type Information (/sys/kernel/btf/vmlinux --> uncompressed)
if [ -r /sys/kernel/btf/vmlinux ]; then
  cat /sys/kernel/btf/vmlinux > "$KERNEL_DIR/btf-vmlinux"
else
  echo "[Info]  BTF not available (CONFIG_DEBUG_INFO_BTF not set)."
fi

# Debug Kernel (vmlinux w/ DWARF) - only if debug symbols are installed
for DBG in "/usr/lib/debug/boot/vmlinux-$KVER" "/usr/lib/debug/lib/modules/$KVER/vmlinux"; do
  if [ -r "$DBG" ]; then
    cp -p "$DBG" "$KERNEL_DIR/vmlinux-$KVER-dbg"
    echo "[Info]  Debug Kernel found: $DBG"
    break
  fi
done

# Secure Archive Container
if [ -f "$SEVENZIP" ]; then
  CONTAINER="$OUTPUT_DIR.7z"
  echo "[Info]  Preparing Secure Archive Container [time-consuming-task] ... "
  "$SEVENZIP" a -t7z -mx0 -mhe=on -p"$ARCHIVE_PASSWORD" "$CONTAINER" "$OUTPUT_DIR" > /dev/null 2>&1 \
    && "$SEVENZIP" t -p"$ARCHIVE_PASSWORD" "$CONTAINER" > /dev/null 2>&1
  CONTAINER_OK=$?
else
  # Fallback for architectures without 7-Zip (e.g. 32-bit ARM) --> NO encryption
  CONTAINER="$OUTPUT_DIR.tar"
  echo "[Info]  Preparing Archive Container w/ tar [time-consuming-task] ... "
  tar -cf "$CONTAINER" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" > /dev/null 2>&1 \
    && tar -tf "$CONTAINER" > /dev/null 2>&1
  CONTAINER_OK=$?
fi

if [ "$CONTAINER_OK" -eq 0 ]; then
  echo "[Info]  Archive Container: $(basename "$CONTAINER")"

  # Archive File Size
  BYTES=$(stat -c %s "$CONTAINER")
  FILESIZE=$(echo "$BYTES" | awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
  echo "[Info]  Total Archive Size: $FILESIZE"

  # Info Message (tar only)
  if [ ! -f "$SEVENZIP" ]; then
    echo "${YELLOW}[Info]  Archive Container is NOT encrypted (7-Zip NOT available for $ARCH).${RESET}" 1>&2
  fi

  # Cleaning up (only after successful verification)
  rm -rf "$OUTPUT_DIR"
else
  echo "[Error] Archive Container failed. Output folder was NOT deleted." 1>&2
fi

}

#############################################################################################################################################################################################

LiME()

{

# LiME - Linux Memory Extractor

# LiME is Loadable Kernel Module (LKM). LiME ships with a default Makefile that should be suitable for compilation on most modern Linux systems.

# Check if the script is being run as root
if [[ $EUID -ne 0 ]]; then
	echo "[Error] This script must be run as root." 1>&2
	echo ""
	exit 1
fi

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Create Output Directories
mkdir -p "$OUTPUT_DIR/SystemInfo"
mkdir -p "$OUTPUT_DIR/Memory"

# Kernel Lockdown
LOCKDOWN_FILE="/sys/kernel/security/lockdown"

if [ -r "$LOCKDOWN_FILE" ]; then
  KERNEL_LOCKDOWN=$(grep -o '\[[a-z]*\]' "$LOCKDOWN_FILE" | tr -d '[]')
  echo "$KERNEL_LOCKDOWN" > "$OUTPUT_DIR"/SystemInfo/Kernel-Lockdown.txt
  if [ "$KERNEL_LOCKDOWN" != "none" ]; then
    echo "[Error] Kernel Lockdown is ACTIVE. Memory Acquisition is NOT possible." 1>&2
    echo "" 1>&2
    exit 1
  fi
else
  echo "[Info]  Kernel Lockdown: not available (not supported by kernel)"
fi

# Processor Architecture (Kernel)
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    SEVENZIP="$SCRIPT_DIR/Tools/7-Zip/x86-64/7zz"
    ;;
  aarch64|arm64)
    SEVENZIP="$SCRIPT_DIR/Tools/7-Zip/arm64/7zz"
    ;;
  *)
    echo "[Error] Unsupported Processor Architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Short Hostname
echo "[Info]  Host Name: $HOST_NAME"

# Total Physical Memory Size
RAM_MB=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
if [ -z "$RAM_MB" ] || [ "$RAM_MB" -eq 0 ]; then
  echo "[Error] Could not determine Total Physical Memory Size." 1>&2
  echo "" 1>&2
  exit 1
fi
RAM_GB=$(awk -v mb="$RAM_MB" 'BEGIN {printf "%.1f", mb / 1024}')
echo "[Info]  Total Physical Memory Size: $RAM_GB GB"

# Safety Guardrail (restrict volatile memory dumps to 256 GB or less)
# Note: Prevents severe disk exhaustion, excessive memory smearing, OOM crashes and kernel panics on systems with more than 256 GB of memory.
MAX_MEMORY_MB=262144 # 256 GB (256 * 1024 MB)
if (( RAM_MB > MAX_MEMORY_MB )); then
  echo "[Error] Total System Memory ($RAM_GB GB) exceeds the limit of 256 GB." 1>&2
  echo "" 1>&2
  exit 1
fi

# Required Disk Space (Physical Memory + 12.5% Safety Margin)
REQUIRED_MB=$(( RAM_MB + RAM_MB / 8 ))

# Check Available Disk Space
AVAILABLE_MB=$(df -Pm "$OUTPUT_DIR" | awk 'NR==2 {print $4}')
if (( AVAILABLE_MB < REQUIRED_MB )); then
	echo "[Error] Not enough disk space to save memory dump file." 1>&2
	echo "[Error] Required: $REQUIRED_MB MB, Available: $AVAILABLE_MB MB" 1>&2
	echo "" 1>&2
	exit 1
fi

# Memory Acquisition (uncompressed LiME image)
LIME_SRC="$SCRIPT_DIR/Tools/LiME/src"
LIME_OUT="$OUTPUT_DIR/Memory/LiME"
KVER="$(uname -r)"
LKM="lime-$KVER.ko"
MEMORY_DUMP="$HOST_NAME"_LiME.lime

mkdir -p "$LIME_OUT/build"

# Kbuild (M=) and LiME (path=) can't handle spaces in paths
for DIR in "$LIME_SRC" "$LIME_OUT"; do
    if [[ "$DIR" == *" "* ]]; then
        echo "[Error] Path contains spaces: $DIR" 1>&2
        echo "[Error] Please rename the folder/volume (e.g. 'T7 Shield' -> 'T7_Shield')." 1>&2
        exit 1
    fi
done

# Kernel headers are required to build the LKM
if [ ! -d "/lib/modules/$KVER/build" ]; then
    echo "[Error] Kernel headers for $KVER NOT found (e.g. linux-headers-$KVER)." 1>&2
    exit 1
fi

# Compiling Loadable Kernel Module (LKM)
echo "[Info]  Compiling Loadable Kernel Module (LKM) ... "
if ! ( cd "$LIME_SRC" && make ) > "$LIME_OUT/build/make.txt" 2>&1 || [ ! -f "$LIME_SRC/$LKM" ]; then
    echo "[Error] Compilation failed. See: $LIME_OUT/build/make.txt" 1>&2
    exit 1
fi

# Unload a leftover LiME module from a previous run
if lsmod | grep -q "^lime "; then
    /sbin/rmmod lime
fi

# Memory Acquisition w/ LiME
echo "[Info]  Creating Memory Snapshot w/ LiME [approx. 1-5 min.] ... "
if ! /sbin/insmod "$LIME_SRC/$LKM" "path=$LIME_OUT/$MEMORY_DUMP" "format=lime" "digest=md5"; then # digest=sha256
    echo "[Error] insmod failed. Check: dmesg | tail" 1>&2
    exit 1
fi

# Unloading Kernel Module
echo -n "[Info]  Unloading Kernel Module ... "
if ! lsmod | grep -q "^lime "; then
    # Case: Module is not currently loaded
    echo "Skipped (not loaded)"
elif RMMOD_ERR=$(/sbin/rmmod lime 2>&1); then
    # Case: Success (no output)
    echo "Done!"
elif [[ "$RMMOD_ERR" == *"in use"* ]]; then
    # Case: Module is in use
    echo "Failed!"
    echo "[Error] LiME module is in use (acquisition still running?)." 1>&2
else
    echo "Failed!"
    echo "[Error] $RMMOD_ERR" 1>&2
fi

# Verify Output
if [ ! -s "$LIME_OUT/$MEMORY_DUMP" ]; then
    echo "[Error] Memory dump is missing or empty: $LIME_OUT/$MEMORY_DUMP" 1>&2
    exit 1
fi

if [ -s "$LIME_OUT/$MEMORY_DUMP.md5" ]; then
    LIME_MD5=$(awk '{print toupper($1)}' "$LIME_OUT/$MEMORY_DUMP.md5")
    echo "[Info]  MD5 Hash: $LIME_MD5"
else
    echo "[Warning] MD5 file NOT found: $LIME_OUT/$MEMORY_DUMP.md5"
fi

mv "$LIME_SRC/$LKM" "$LIME_OUT/build/"
( cd "$LIME_SRC" && make clean ) > /dev/null 2>&1

# Compressing Memory Snapshot
ARCHIVE_NAME="${HOST_NAME}_LiME.7z"
FILE="$LIME_OUT/$MEMORY_DUMP"
if [ -f "$FILE" ]; then
  FILES=("$MEMORY_DUMP")
  [ -s "$FILE.md5" ] && FILES+=("$MEMORY_DUMP.md5")

  echo "[Info]  Compressing Memory Snapshot [time-consuming-task] [approx. 10-60 min.] ... "
  if ( cd "$LIME_OUT" \
       && "$SEVENZIP" a -t7z -mx5 -mhe=on -p"$ARCHIVE_PASSWORD" "$ARCHIVE_NAME" "${FILES[@]}" \
       && "$SEVENZIP" t -p"$ARCHIVE_PASSWORD" "$ARCHIVE_NAME" ) > "$LIME_OUT/7-Zip.txt" 2>&1; then
    echo "[Info]  Archive Name: $ARCHIVE_NAME"

    # Cleaning up (only after successful verification)
    rm -f "$FILE" "$FILE.md5" "$LIME_OUT/7-Zip.txt"
  else
    echo "[Error] Archive creation or verification failed. Memory Snapshot was NOT deleted. See 7-Zip.txt" 1>&2
  fi
fi

# Archive Size
FILE="$LIME_OUT/$ARCHIVE_NAME"
if [ -f "$FILE" ]; then
  BYTES=$(stat -c %s "$FILE")
  FILESIZE=$(echo "$BYTES" | awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
  echo "[Info]  Archive Size: $FILESIZE"

  # Create Time
  EPOCH=$(stat -c %W "$FILE" 2>/dev/null)
  if [ -n "$EPOCH" ] && [ "$EPOCH" != "0" ] && [ "$EPOCH" != "?" ]; then
    BIRTH=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S')
    echo "[Info]  Create Time: $BIRTH UTC"
  else
    echo "[Info]  Create Time: not available (not supported by file system)"
  fi

  # Last Modified Time
  EPOCH=$(stat -c %Y "$FILE")
  MODIFY=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S')
  echo "[Info]  Last Modified Time: $MODIFY UTC"
fi

# Basic System Information
echo "[Info]  Collecting Basic System Information ... "

# Hostname
cat /etc/hostname > "$OUTPUT_DIR"/SystemInfo/Hostname.txt
command -v hostnamectl > /dev/null && hostnamectl > "$OUTPUT_DIR"/SystemInfo/hostnamectl.txt 2> /dev/null

# OS Release Information
cat /etc/os-release > "$OUTPUT_DIR"/SystemInfo/OS-Release.txt

if [ -f /etc/centos-release ]; then
	cat /etc/centos-release > "$OUTPUT_DIR"/SystemInfo/CentOS-Release.txt 2> /dev/null
fi

if [ -f /etc/redhat-release ]; then
	cat /etc/redhat-release > "$OUTPUT_DIR"/SystemInfo/RedHat-Release.txt 2> /dev/null
fi

# System Uptime
uptime > "$OUTPUT_DIR"/SystemInfo/uptime.txt 2> /dev/null

if [ -f "$OUTPUT_DIR"/SystemInfo/OS-Release.txt ] && grep -q "Ubuntu" "$OUTPUT_DIR"/SystemInfo/OS-Release.txt; then
	uptime -p > "$OUTPUT_DIR"/SystemInfo/uptime-pretty.txt 2> /dev/null
	uptime -s > "$OUTPUT_DIR"/SystemInfo/uptime-since.txt 2> /dev/null
fi

# Timezone Information
command -v timedatectl > /dev/null && timedatectl > "$OUTPUT_DIR"/SystemInfo/timedatectl.txt 2> /dev/null

if [ -f /etc/timezone ]; then
	cat /etc/timezone > "$OUTPUT_DIR"/SystemInfo/Timezone.txt 2> /dev/null
fi

# Machine Hardware Name
MACHINE=$(uname -m)
echo "$MACHINE" > "$OUTPUT_DIR"/SystemInfo/Machine-Hardware-Name.txt

# Kernel Release
KERNEL_RELEASE=$(uname -r)
echo "$KERNEL_RELEASE" > "$OUTPUT_DIR"/SystemInfo/Kernel-Release.txt

# Kernel Name
KERNEL_NAME=$(uname -s)
echo "$KERNEL_NAME" > "$OUTPUT_DIR"/SystemInfo/Kernel-Name.txt

# Linux Profile Name
PRETTY_NAME=$(. /etc/os-release && echo "$PRETTY_NAME")
echo "[Info]  $PRETTY_NAME $MACHINE ($KERNEL_RELEASE)"

# Mapping Layout
KVER=$(uname -r)
MAPPING_DIR="$OUTPUT_DIR/Memory/Mapping-Layout"
echo "[Info]  Collecting Mapping Layout ... "
mkdir -p "$MAPPING_DIR"

# Collecting System.map (Static Symbol File)
if [ -r "/boot/System.map-$KVER" ]; then
	cp -p "/boot/System.map-$KVER" "$MAPPING_DIR/"
else
	echo "[Warning] /boot/System.map-$KVER NOT found." 1>&2
fi

# Collecting Kernel Symbols at Runtime (incl. KASLR addresses)
KALLSYMS="$MAPPING_DIR/kallsyms.txt"
cat /proc/kallsyms > "$KALLSYMS"

# Addresses are hidden only if ALL lines start with zeros
if ! grep -q -v '^0\+ ' "$KALLSYMS"; then
  KPTR_RESTRICT=$(cat /proc/sys/kernel/kptr_restrict)
  echo "[Info]  kallsyms addresses are hidden (kernel.kptr_restrict=$KPTR_RESTRICT). Temporarily disabling restriction ..."

  # Disable Kernel Pointer Restriction, dump kallsyms (this can act as your System.map replacement), restore original value immediately
  echo 0 > /proc/sys/kernel/kptr_restrict
  cat /proc/kallsyms > "$KALLSYMS"
  echo "$KPTR_RESTRICT" > /proc/sys/kernel/kptr_restrict
  echo "[Info]  kernel.kptr_restrict restored to $KPTR_RESTRICT."

  if ! grep -q -v '^0\+ ' "$KALLSYMS"; then
    echo "[Warning] kallsyms addresses are still hidden." 1>&2
  fi
fi

# Kernel Banner (Volatility 3 matches symbol tables by this banner)
cat /proc/version > "$MAPPING_DIR/version.txt"
uname -a > "$MAPPING_DIR/uname.txt"

# Kernel Config & Distribution
[ -r "/boot/config-$KVER" ] && cp -p "/boot/config-$KVER" "$MAPPING_DIR/"
[ -r /etc/os-release ] && cp -p /etc/os-release "$MAPPING_DIR/os-release.txt"

# Collecting Kernel Image (compressed, extract offline w/ extract-vmlinux)
# https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
KVER=$(uname -r)
KERNEL_DIR="$OUTPUT_DIR/Memory/Kernel-Image"
echo "[Info]  Collecting Kernel Image ..."
mkdir -p "$KERNEL_DIR"
if [ -r "/boot/vmlinuz-$KVER" ]; then
  cp -p "/boot/vmlinuz-$KVER" "$KERNEL_DIR/"
else
  # Fallback: Boot image from kernel command line (set by GRUB)
  BOOT_IMAGE=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^BOOT_IMAGE=//p')
  BOOT_IMAGE="${BOOT_IMAGE#\(*\)}" # strip GRUB device prefix, e.g. (hd0,gpt2)
  if [ -n "$BOOT_IMAGE" ] && [ -r "$BOOT_IMAGE" ]; then
    cp -p "$BOOT_IMAGE" "$KERNEL_DIR/"
  elif [ -n "$BOOT_IMAGE" ] && [ -r "/boot$BOOT_IMAGE" ]; then
    cp -p "/boot$BOOT_IMAGE" "$KERNEL_DIR/"
  else
    echo "[Error] Kernel image NOT found." 1>&2
  fi
fi

# BTF Type Information (/sys/kernel/btf/vmlinux --> uncompressed)
if [ -r /sys/kernel/btf/vmlinux ]; then
  cat /sys/kernel/btf/vmlinux > "$KERNEL_DIR/btf-vmlinux"
else
  echo "[Info]  BTF not available (CONFIG_DEBUG_INFO_BTF not set)."
fi

# Debug Kernel (vmlinux w/ DWARF) - only if debug symbols are installed
for DBG in "/usr/lib/debug/boot/vmlinux-$KVER" "/usr/lib/debug/lib/modules/$KVER/vmlinux"; do
  if [ -r "$DBG" ]; then
    cp -p "$DBG" "$KERNEL_DIR/vmlinux-$KVER-dbg"
    echo "[Info]  Debug kernel found: $DBG"
    break
  fi
done

# Check if 7zz exists
if [ -f "$SEVENZIP" ]; then
  # Preparing Secure Archive Container
  echo "[Info]  Preparing Secure Archive Container [time-consuming-task] ... "
  if "$SEVENZIP" a -t7z -mx0 -mhe=on -p"$ARCHIVE_PASSWORD" "$OUTPUT_DIR.7z" "$OUTPUT_DIR" > /dev/null 2>&1 \
     && "$SEVENZIP" t -p"$ARCHIVE_PASSWORD" "$OUTPUT_DIR.7z" > /dev/null 2>&1; then

    # Archive File Size
    BYTES=$(stat -c %s "$OUTPUT_DIR.7z")
    FILESIZE=$(echo "$BYTES" | awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
    echo "[Info]  Total Archive Size: $FILESIZE"

    # Cleaning up (only after successful verification)
    rm -rf "$OUTPUT_DIR"
  else
    echo "[Error] Secure Archive Container failed. Output folder was NOT deleted." 1>&2
  fi
else
  echo "[Error] 7-Zip NOT found." 1>&2
fi

}

#############################################################################################################################################################################################

DumpIt()
{

# MAGNET DumpIt for Linux - Linux memory acquisition that makes sense.

# Note: DumpIt reads /proc/kcore and creates a Linux ELF Core image (compatible w/ gdb, crash, drgn and Volatility 3). No kernel module required.

# dumpitforlinux-x86_64  - Static binary (musl) for x86_64 (64-bit Intel/AMD) Linux environments.
# dumpitforlinux-aarch64 - Static binary (musl) for ARM64 (64-bit ARM) Linux environments.

# Check if the script is being run as root
if [[ $EUID -ne 0 ]]; then
  echo "[Error] This script must be run as root." 1>&2
  echo ""
  exit 1
fi

# Acquisition date (ISO 8601)
echo -n "Acquisition date: "; date -u +"%Y-%m-%d %H:%M:%S UTC"
echo ""

# Create Output Directories
mkdir -p "$OUTPUT_DIR/SystemInfo"
mkdir -p "$OUTPUT_DIR/Memory"

# Kernel Lockdown
LOCKDOWN_FILE="/sys/kernel/security/lockdown"

if [ -r "$LOCKDOWN_FILE" ]; then
  KERNEL_LOCKDOWN=$(grep -o '\[[a-z]*\]' "$LOCKDOWN_FILE" | tr -d '[]')
  echo "$KERNEL_LOCKDOWN" > "$OUTPUT_DIR"/SystemInfo/Kernel-Lockdown.txt
  if [ "$KERNEL_LOCKDOWN" != "none" ]; then
    echo "[Error] Kernel Lockdown is ACTIVE. Memory Acquisition is NOT possible." 1>&2
    echo "" 1>&2
    exit 1
  fi
else
  echo "[Info]  Kernel Lockdown: not available (not supported by kernel)"
fi

# Processor Architecture (Kernel)
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    DUMPIT="$SCRIPT_DIR/Tools/DumpIt/dumpitforlinux-x86_64"
    DUMPIT_SHA256="EEF3F1289784DC37F3ED268263A51C11A33EEC9B7158063215D0BABC44F9D3C5"
    SEVENZIP="$SCRIPT_DIR/Tools/7-Zip/x86-64/7zz"
    ;;
  aarch64|arm64)
    DUMPIT="$SCRIPT_DIR/Tools/DumpIt/dumpitforlinux-aarch64"
    DUMPIT_SHA256="1A3795D5D9A84B43DC08031D061896DBA88D23BC5E8ECDF3070A743E0269BAB2"
    SEVENZIP="$SCRIPT_DIR/Tools/7-Zip/arm64/7zz"
    ;;
  *)
    echo "[Error] Unsupported Processor Architecture: $ARCH" >&2
    exit 1
    ;;
esac

# Short Hostname
echo "[Info]  Host Name: $HOST_NAME"

# Total Physical Memory Size
RAM_MB=$(awk '/^MemTotal:/ {print int($2 / 1024)}' /proc/meminfo)
if [ -z "$RAM_MB" ] || [ "$RAM_MB" -eq 0 ]; then
  echo "[Error] Could not determine Total Physical Memory Size." 1>&2
  echo "" 1>&2
  exit 1
fi
RAM_GB=$(awk -v mb="$RAM_MB" 'BEGIN {printf "%.1f", mb / 1024}')
echo "[Info]  Total Physical Memory Size: $RAM_GB GB"

# Check if /proc/kcore is available (required by DumpIt)
if [ ! -r /proc/kcore ]; then
  echo "[Error] /proc/kcore NOT available (CONFIG_PROC_KCORE not set). Memory Acquisition w/ DumpIt is NOT possible." 1>&2
  echo "" 1>&2
  exit 1
fi

# Check if the binary exists (DumpIt)
if [ ! -f "$DUMPIT" ]; then
  echo "[Error] DumpIt binary not found: $DUMPIT" >&2
  exit 1
fi

# Verify File Integrity (DumpIt)
HASH=$(sha256sum "$DUMPIT" | awk '{print toupper($1)}')
if [ "$HASH" = "$DUMPIT_SHA256" ]; then
  echo "[Info]  File Integrity (DumpIt for Linux): OK"
else
  echo "${RED}[ALERT] File Integrity (DumpIt for Linux): FAILURE${RESET}" 1>&2
  echo "" 1>&2
  exit 1
fi

# Check if the binary can be executed (DumpIt)
if [ ! -x "$DUMPIT" ]; then
  chmod +x "$DUMPIT" 2>/dev/null || { echo "[Error] $DUMPIT is not executable." >&2; exit 1; }
fi

# Safety Guardrail (restrict volatile memory dumps to 256 GB or less)
# Note: Prevents severe disk exhaustion, excessive memory smearing, OOM crashes and kernel panics on systems with more than 256 GB of memory.
MAX_MEMORY_MB=262144 # 256 GB (256 * 1024 MB)
if (( RAM_MB > MAX_MEMORY_MB )); then
  echo "[Error] Total System Memory ($RAM_GB GB) exceeds the limit of 256 GB." 1>&2
  echo "" 1>&2
  exit 1
fi

# Required Disk Space (Physical Memory + 12.5% Safety Margin)
REQUIRED_MB=$(( RAM_MB + RAM_MB / 8 ))

# Check Available Disk Space
AVAILABLE_MB=$(df -Pm "$OUTPUT_DIR" | awk 'NR==2 {print $4}')
if (( AVAILABLE_MB < REQUIRED_MB )); then
  echo "[Error] Not enough disk space to save memory dump file." 1>&2
  echo "[Error] Required: $REQUIRED_MB MB, Available: $AVAILABLE_MB MB" 1>&2
  echo "" 1>&2
  exit 1
fi

# Memory Acquisition (Linux ELF Core image)
DUMP_DIR="$OUTPUT_DIR/Memory/DumpIt"
DUMP_NAME="${HOST_NAME}_DumpIt.core"
ARCHIVE_NAME="${HOST_NAME}_DumpIt.7z"
FILE="$DUMP_DIR/$DUMP_NAME"
DUMPIT_LOG="$DUMP_DIR/DumpIt-Log.txt"
echo "[Info]  Creating Memory Snapshot w/ DumpIt for Linux [approx. 1-5 min.] ... "
mkdir -p "$DUMP_DIR"
"$DUMPIT" -r "$FILE" > "$DUMPIT_LOG" 2>&1
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ] && [ -s "$FILE" ]; then
  # Remove Log (progress bar output only)
  rm -f "$DUMPIT_LOG"
else
  echo "[Error] Memory Acquisition failed (Exit Code: $EXIT_CODE). See DumpIt-Log.txt" 1>&2
  echo "" 1>&2
  exit 1
fi

# MD5 Calculation
echo "[Info]  Calculating MD5 checksum of Memory Snapshot [approx. 1-5 min.] ... "
MD5=$(md5sum "$FILE" | awk '{print toupper($1)}')
echo "$MD5" > "$DUMP_DIR/MD5.txt"
echo "[Info]  MD5 Hash: $MD5"

# Compressing Memory Snapshot
echo "[Info]  Compressing Memory Snapshot [time-consuming-task] [approx. 10-60 min.] ... "
if ( cd "$DUMP_DIR" \
     && "$SEVENZIP" a -t7z -mx5 -mhe=on -p"$ARCHIVE_PASSWORD" "$ARCHIVE_NAME" "$DUMP_NAME" MD5.txt \
     && "$SEVENZIP" t -p"$ARCHIVE_PASSWORD" "$ARCHIVE_NAME" ) > "$DUMP_DIR/7-Zip.txt" 2>&1; then
  echo "[Info]  Archive Name: $ARCHIVE_NAME"

  # Cleaning up (only after successful verification)
  rm -f "$FILE" "$DUMP_DIR/MD5.txt" "$DUMP_DIR/7-Zip.txt"
else
  echo "[Error] Archive creation or verification failed. Memory Snapshot was NOT deleted. See 7-Zip.txt" 1>&2
fi

# Archive Size
FILE="$DUMP_DIR/$ARCHIVE_NAME"
if [ -f "$FILE" ]; then
  BYTES=$(stat -c %s "$FILE")
  FILESIZE=$(echo "$BYTES" | awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
  echo "[Info]  Archive Size: $FILESIZE"

  # Create Time
  EPOCH=$(stat -c %W "$FILE" 2>/dev/null)
  if [ -n "$EPOCH" ] && [ "$EPOCH" != "0" ] && [ "$EPOCH" != "?" ]; then
    BIRTH=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S')
    echo "[Info]  Create Time: $BIRTH UTC"
  else
    echo "[Info]  Create Time: not available (not supported by file system)"
  fi

  # Last Modified Time
  EPOCH=$(stat -c %Y "$FILE")
  MODIFY=$(date -u -d "@$EPOCH" '+%Y-%m-%d %H:%M:%S')
  echo "[Info]  Last Modified Time: $MODIFY UTC"
fi

# DumpIt Version
DUMPIT_VERSION=$("$DUMPIT" -V 2>/dev/null | awk '/^dumpitforlinux/ {print $2}')
echo "$DUMPIT_VERSION" > "$OUTPUT_DIR"/Memory/DumpIt-Version.txt

# Basic System Information
echo "[Info]  Collecting Basic System Information ... "

# Hostname
cat /etc/hostname > "$OUTPUT_DIR"/SystemInfo/Hostname.txt
command -v hostnamectl > /dev/null && hostnamectl > "$OUTPUT_DIR"/SystemInfo/hostnamectl.txt 2> /dev/null

# OS Release Information
cat /etc/os-release > "$OUTPUT_DIR"/SystemInfo/OS-Release.txt

if [ -f /etc/centos-release ]; then
  cat /etc/centos-release > "$OUTPUT_DIR"/SystemInfo/CentOS-Release.txt 2> /dev/null
fi

if [ -f /etc/redhat-release ]; then
  cat /etc/redhat-release > "$OUTPUT_DIR"/SystemInfo/RedHat-Release.txt 2> /dev/null
fi

# System Uptime
uptime > "$OUTPUT_DIR"/SystemInfo/uptime.txt 2> /dev/null

if [ -f "$OUTPUT_DIR"/SystemInfo/OS-Release.txt ] && grep -q "Ubuntu" "$OUTPUT_DIR"/SystemInfo/OS-Release.txt; then
  uptime -p > "$OUTPUT_DIR"/SystemInfo/uptime-pretty.txt 2> /dev/null
  uptime -s > "$OUTPUT_DIR"/SystemInfo/uptime-since.txt 2> /dev/null
fi

# Timezone Information
command -v timedatectl > /dev/null && timedatectl > "$OUTPUT_DIR"/SystemInfo/timedatectl.txt 2> /dev/null

if [ -f /etc/timezone ]; then
  cat /etc/timezone > "$OUTPUT_DIR"/SystemInfo/Timezone.txt 2> /dev/null
fi

# Machine Hardware Name
MACHINE=$(uname -m)
echo "$MACHINE" > "$OUTPUT_DIR"/SystemInfo/Machine-Hardware-Name.txt

# Kernel Release
KERNEL_RELEASE=$(uname -r)
echo "$KERNEL_RELEASE" > "$OUTPUT_DIR"/SystemInfo/Kernel-Release.txt

# Kernel Name
KERNEL_NAME=$(uname -s)
echo "$KERNEL_NAME" > "$OUTPUT_DIR"/SystemInfo/Kernel-Name.txt

# Linux Profile Name
PRETTY_NAME=$(. /etc/os-release && echo "$PRETTY_NAME")
echo "[Info]  $PRETTY_NAME $MACHINE ($KERNEL_RELEASE)"

# Mapping Layout
KVER=$(uname -r)
MAPPING_DIR="$OUTPUT_DIR/Memory/Mapping-Layout"
echo "[Info]  Collecting Mapping Layout ... "
mkdir -p "$MAPPING_DIR"

# Collecting System.map (Static Symbol File)
if [ -r "/boot/System.map-$KVER" ]; then
  cp -p "/boot/System.map-$KVER" "$MAPPING_DIR/"
else
  echo "[Warning] /boot/System.map-$KVER NOT found." 1>&2
fi

# Collecting Kernel Symbols at Runtime (incl. KASLR addresses)
KALLSYMS="$MAPPING_DIR/kallsyms.txt"
cat /proc/kallsyms > "$KALLSYMS"

# Addresses are hidden only if ALL lines start with zeros
if ! grep -q -v '^0\+ ' "$KALLSYMS"; then
  KPTR_RESTRICT=$(cat /proc/sys/kernel/kptr_restrict)
  echo "[Info]  kallsyms addresses are hidden (kernel.kptr_restrict=$KPTR_RESTRICT). Temporarily disabling restriction ..."

  # Disable Kernel Pointer Restriction, dump kallsyms (this can act as your System.map replacement), restore original value immediately
  echo 0 > /proc/sys/kernel/kptr_restrict
  cat /proc/kallsyms > "$KALLSYMS"
  echo "$KPTR_RESTRICT" > /proc/sys/kernel/kptr_restrict
  echo "[Info]  kernel.kptr_restrict restored to $KPTR_RESTRICT."

  if ! grep -q -v '^0\+ ' "$KALLSYMS"; then
    echo "[Warning] kallsyms addresses are still hidden." 1>&2
  fi
fi

# Kernel Banner (Volatility 3 matches symbol tables by this banner)
cat /proc/version > "$MAPPING_DIR/version.txt"
uname -a > "$MAPPING_DIR/uname.txt"

# Kernel Config & Distribution
[ -r "/boot/config-$KVER" ] && cp -p "/boot/config-$KVER" "$MAPPING_DIR/"
[ -r /etc/os-release ] && cp -p /etc/os-release "$MAPPING_DIR/os-release.txt"

# Collecting Kernel Image (compressed, extract offline w/ extract-vmlinux)
# https://github.com/torvalds/linux/blob/master/scripts/extract-vmlinux
KVER=$(uname -r)
KERNEL_DIR="$OUTPUT_DIR/Memory/Kernel-Image"
echo "[Info]  Collecting Kernel Image ..."
mkdir -p "$KERNEL_DIR"
if [ -r "/boot/vmlinuz-$KVER" ]; then
  cp -p "/boot/vmlinuz-$KVER" "$KERNEL_DIR/"
else
  # Fallback: Boot image from kernel command line (set by GRUB)
  BOOT_IMAGE=$(tr ' ' '\n' < /proc/cmdline | sed -n 's/^BOOT_IMAGE=//p')
  BOOT_IMAGE="${BOOT_IMAGE#\(*\)}" # strip GRUB device prefix, e.g. (hd0,gpt2)
  if [ -n "$BOOT_IMAGE" ] && [ -r "$BOOT_IMAGE" ]; then
    cp -p "$BOOT_IMAGE" "$KERNEL_DIR/"
  elif [ -n "$BOOT_IMAGE" ] && [ -r "/boot$BOOT_IMAGE" ]; then
    cp -p "/boot$BOOT_IMAGE" "$KERNEL_DIR/"
  else
    echo "[Error] Kernel image NOT found." 1>&2
  fi
fi

# BTF Type Information (/sys/kernel/btf/vmlinux --> uncompressed)
if [ -r /sys/kernel/btf/vmlinux ]; then
  cat /sys/kernel/btf/vmlinux > "$KERNEL_DIR/btf-vmlinux"
else
  echo "[Info]  BTF not available (CONFIG_DEBUG_INFO_BTF not set)."
fi

# Debug Kernel (vmlinux w/ DWARF) - only if debug symbols are installed
for DBG in "/usr/lib/debug/boot/vmlinux-$KVER" "/usr/lib/debug/lib/modules/$KVER/vmlinux"; do
  if [ -r "$DBG" ]; then
    cp -p "$DBG" "$KERNEL_DIR/vmlinux-$KVER-dbg"
    echo "[Info]  Debug Kernel found: $DBG"
    break
  fi
done

# Secure Archive Container
if [ -f "$SEVENZIP" ]; then
  CONTAINER="$OUTPUT_DIR.7z"
  echo "[Info]  Preparing Secure Archive Container [time-consuming-task] ... "
  "$SEVENZIP" a -t7z -mx0 -mhe=on -p"$ARCHIVE_PASSWORD" "$CONTAINER" "$OUTPUT_DIR" > /dev/null 2>&1 \
    && "$SEVENZIP" t -p"$ARCHIVE_PASSWORD" "$CONTAINER" > /dev/null 2>&1
  CONTAINER_OK=$?
else
  # Fallback for architectures without 7-Zip (e.g. 32-bit ARM) --> NO encryption
  CONTAINER="$OUTPUT_DIR.tar"
  echo "[Info]  Preparing Archive Container w/ tar [time-consuming-task] ... "
  tar -cf "$CONTAINER" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")" > /dev/null 2>&1 \
    && tar -tf "$CONTAINER" > /dev/null 2>&1
  CONTAINER_OK=$?
fi

if [ "$CONTAINER_OK" -eq 0 ]; then
  echo "[Info]  Archive Container: $(basename "$CONTAINER")"

  # Archive File Size
  BYTES=$(stat -c %s "$CONTAINER")
  FILESIZE=$(echo "$BYTES" | awk '{ split( "Bytes KB MB GB TB" , v ); s=1; while( $1>1000 ){ $1/=1000; s++ } printf "%.1f %s", $1, v[s] }')
  echo "[Info]  Total Archive Size: $FILESIZE"

  # Info Message (tar only)
  if [ ! -f "$SEVENZIP" ]; then
    echo "${YELLOW}[Info]  Archive Container is NOT encrypted (7-Zip NOT available for $ARCH).${RESET}" 1>&2
  fi

  # Cleaning up (only after successful verification)
  rm -rf "$OUTPUT_DIR"
else
  echo "[Error] Archive Container failed. Output folder was NOT deleted." 1>&2
fi

}

#############################################################################################################################################################################################

Footer()
{
  echo ""
  echo "FINISHED!"

  ELAPSED_TIME=$(( SECONDS - START_TIME ))
  echo "Overall acquisition duration: $(( ELAPSED_TIME / 3600 )) h $(( (ELAPSED_TIME % 3600) / 60 )) min $(( ELAPSED_TIME % 60 )) sec"
  echo ""
}

#############################################################################################################################################################################################

Screenlog()
{
  # Remove ANSI escape codes, carriage returns and [sudo] prompts
  if [ -f "$LOGFILE" ]; then
    mkdir -p "$(dirname "$OUTPUT_DIR")"
    sed -e 's/\x1b\[[0-9;?]*[A-Za-z]//g' -e 's/\r//g' -e 's/\[sudo\] //g' "$LOGFILE" > "${OUTPUT_DIR}_LogFile.txt"
    rm -f "$LOGFILE"
  fi
}

#############################################################################################################################################################################################

# Main

# Argument Parsing
while [ $# -gt 0 ]; do
  case "$1" in
    -a|--avml)
      MODE="avml"
      shift
      ;;
    -d|--dumpit)
      MODE="dumpit"
      shift
      ;;
    -l|--lime)
      MODE="lime"
      shift
      ;;
    -h|--help|\?)
      MODE="help"
      shift
      ;;
    --output-path)
      if [[ -n "$2" && "$2" != -* ]]; then
        OUTPUT_PATH="$2"
        shift 2
      else
        Header
        echo "ERROR   : __main__            : --output-path requires a valid path value"
        echo ""
        Usage 1
      fi
      ;;
    *)
      Header
      echo "ERROR   : __main__            : no such option: $1"
      echo ""
      Usage 1
      ;;
  esac
done

# Custom Output Path
if [ -n "$OUTPUT_PATH" ]; then
  if [ ! -d "$OUTPUT_PATH" ]; then
    Header
    echo "ERROR   : __main__            : Output path does NOT exist: $OUTPUT_PATH"
    echo ""
    exit 1
  fi
  if [ ! -w "$OUTPUT_PATH" ]; then
    Header
    echo "ERROR   : __main__            : Output path is NOT writable: $OUTPUT_PATH"
    echo ""
    exit 1
  fi
  BASE_DIR="$(cd "$OUTPUT_PATH" && pwd)" # absolute path
fi

OUTPUT_DIR="$BASE_DIR/$HOST_NAME/${TIMESTAMP}-Collect-LinuxMemoryDump"
LOGFILE="$SCRIPT_DIR/screenlog-draft.txt"

case "$MODE" in
  avml)
  {
  Header
  AVML
  Footer
  } 2>&1 | tee "$LOGFILE"
  EXIT_CODE=${PIPESTATUS[0]}
  Screenlog
  exit "$EXIT_CODE"
  ;;
  dumpit)
  {
  Header
  DumpIt
  Footer
  } 2>&1 | tee "$LOGFILE"
  EXIT_CODE=${PIPESTATUS[0]}
  Screenlog
  exit "$EXIT_CODE"
  ;;
  lime)
  {
  Header
  LiME
  Footer
  } 2>&1 | tee "$LOGFILE"
  EXIT_CODE=${PIPESTATUS[0]}
  Screenlog
  exit "$EXIT_CODE"
  ;;
  help)
  Header
  Usage
  ;;
  "")
  Header
  echo "ERROR   : __main__            : You must specify something to do (try -h)"
  echo ""
  Usage 1
  ;;
esac
