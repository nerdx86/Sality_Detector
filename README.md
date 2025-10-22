# Sality Malware Detector

A Rust-based Windows registry scanner designed to detect indicators of Sality malware infection.

## About Sality

Sality is a polymorphic file infector and botnet malware family that has been active since 2003. It spreads by infecting executable files and uses various techniques to maintain persistence and evade detection, including:

- Creating registry entries with randomized names
- Disabling Windows security features (UAC, Windows Defender, Firewall)
- Deleting SafeBoot registry keys to prevent Safe Mode boot
- Hiding files by modifying Explorer settings

## What This Tool Detects

### 1. Autorun Persistence Locations

Displays all entries from common autorun registry keys:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`

Sality variants often add themselves to these locations for persistence.

### 2. Suspicious Random Registry Keys

Scans for registry keys matching Sality's pattern: `HKCU\Software\{RandomChars}\{RandomNumbers}`

Detection uses multiple heuristics:
- **Dictionary Filtering**: Excludes 100+ known legitimate software vendors (Microsoft, Google, Adobe, etc.)
- **Shannon Entropy Analysis**: Calculates character distribution
  - Normal English text: 3.5-4.0 bits/character
  - Random strings: 4.2+ bits/character
- **Consonant-to-Vowel Ratio**: Random generators often produce consonant-heavy strings (>70%)
- **Numeric Subkeys**: Common Sality pattern uses all-numeric subkey names

### 3. Security Settings Tampering

Checks for registry values indicating disabled security features:

**Security Center Settings:**
- `HKLM\SOFTWARE\Microsoft\Security Center`
  - `AntiVirusOverride = 1`
  - `AntiVirusDisableNotify = 1`

- `HKLM\SOFTWARE\Microsoft\Security Center\Svc`
  - `AntiVirusDisableNotify = 1`
  - `FirewallDisableNotify = 1`
  - `FirewallOverride = 1`
  - `UpdatesDisableNotify = 1`
  - `UacDisableNotify = 1`

**System Policy:**
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`
  - `EnableLUA = 0` (UAC disabled)

**Firewall Settings:**
- `HKLM\SYSTEM\ControlSet001\services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`
  - `EnableFirewall = 0`
  - `DoNotAllowExceptions = 0`
  - `DisableNotifications = 1`

**Explorer Settings (Hidden Files):**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced`
  - `Hidden = 2` (Don't show hidden files)
  - `ShowSuperHidden = 0` (Hide protected OS files)

### 4. SafeBoot Modifications

Enumerates and displays the complete SafeBoot registry structure:
- `HKLM\SYSTEM\CurrentControlSet\Control\SafeBoot`

Sality variants may recursively delete all values and subkeys under SafeBoot to prevent Windows from booting into Safe Mode, making removal more difficult.

## Usage

### Building from Source

```
cargo build --release
```

The optimized executable will be in `target\release\sality_detector.exe` (approximately 1.3MB).

### Running the Scanner

```
cargo run --release
```

Or run the compiled executable directly:

```
target\release\sality_detector.exe
```

**Note**: Administrator privileges may be required to read some HKLM registry keys.

### Example Output

#### Clean System

```
[*] Checking for Suspicious Random Keys:
=========================================

  No suspicious random keys detected.

[*] Checking Security Settings Tampering:
==========================================

Security Center Settings:

System Policy Settings:

Firewall Settings:

Explorer Settings (Hidden Files):
```

#### Infected System

```
[*] Checking for Suspicious Random Keys:
=========================================

[SUSPICIOUS] [HKCU\Software\Xjkwnfrb\19283746]
  Reason: Random-looking key name with numeric subkey
  Entropy: 4.58 (normal English: 3.5-4.0, random: 4.2+)
  value1 = RegValue(REG_SZ: C:\Users\...\malware.exe)

[*] Checking Security Settings Tampering:
==========================================

Security Center Settings:
  [HIT] [SOFTWARE\Microsoft\Security Center]\AntiVirusDisableNotify = 1
  [HIT] [SOFTWARE\Microsoft\Security Center\Svc]\FirewallDisableNotify = 1

System Policy Settings:
  [HIT] [SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]\EnableLUA = 0

Explorer Settings (Hidden Files):
  [HIT] [Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced]\ShowSuperHidden = 0
```

## Detection Methodology

### Random Key Detection Algorithm

1. **Dictionary Check**: Reject keys containing known legitimate vendor names
2. **Entropy Calculation**: Apply Shannon entropy formula to measure randomness
3. **Pattern Analysis**: Check consonant ratio and absence of dictionary substrings
4. **Structure Validation**: Confirm numeric subkey pattern (Sality signature)

A key is flagged as suspicious when:
- High entropy (>4.2) AND (high consonant ratio OR no dictionary words), OR
- High consonant ratio AND no dictionary words
- AND has numeric-only subkeys

### False Positives

While this tool minimizes false positives through multi-factor analysis, some legitimate software may occasionally trigger alerts if it:
- Uses randomly generated installation IDs as registry keys
- Has unusual naming conventions not in the dictionary

Always investigate flagged entries before taking action.

## Windows Defender False Positive

This tool may be flagged by Windows Defender as `Trojan:Win32/Wacatac.B!ml` due to:
- Registry enumeration behavior mimicking malware reconnaissance
- Querying security-related registry keys (Security Center, UAC, Firewall)
- Machine learning heuristics detecting suspicious patterns

This is a false positive. The tool only reads registry values and does not modify anything.

**Mitigation**:
- Review the source code (all functionality is transparent)
- Add an exclusion in Windows Security for the build directory
- Submit a false positive report to Microsoft
- Compile from source yourself to verify integrity

## Build Optimizations

The release build includes:
- LTO (Link-Time Optimization)
- Size optimization (`opt-level = "z"`)
- Debug symbol stripping
- Single codegen unit for maximum optimization

## Technical Details

**Language**: Rust 2024 edition
**Dependencies**:
- `winreg` - Windows registry access
- `regex` - Pattern matching
- `lazy_static` - Static dictionary initialization

**Supported Platforms**: Windows (x86_64)

## License

This tool is provided as-is for malware detection and research purposes.

## Disclaimer

This tool is for defensive security purposes only. It performs read-only operations on the Windows registry and does not modify system settings or remove malware. Always use proper malware removal tools and professional assistance when dealing with infections.
