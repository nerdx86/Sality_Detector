# Sality Malware Detector

A Rust-based Windows registry scanner designed to detect indicators of Sality malware infection.

## About Sality

Sality is a polymorphic file infector and botnet malware family that has been active since 2003. It spreads by infecting executable files and uses various techniques to maintain persistence and evade detection, including:

- Hijacking file associations (.exe, .com) to intercept all program executions
- Modifying Winlogon to execute at system startup
- Creating registry entries with randomized names
- Disabling Windows security features (UAC, Windows Defender, Firewall)
- Disabling Task Manager and Registry Editor to prevent removal
- Deleting SafeBoot registry keys to prevent Safe Mode boot
- Hiding files by modifying Explorer settings
- Using DLL injection via AppInit_DLLs

## What This Tool Detects

### 1. Autorun Persistence Locations

Displays all entries from common autorun registry keys:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`
- `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce`
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler`

Sality variants often add themselves to these locations for persistence.

### 2. Winlogon Hijacking

Checks critical Winlogon registry values for modifications:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
  - **Shell**: Should be "explorer.exe" (launches Windows Explorer)
  - **Userinit**: Should be "C:\Windows\system32\userinit.exe," (user initialization)

Sality may modify these to execute malicious code at every user login. Multiple executables in Userinit or unexpected Shell values indicate infection.

### 3. File Association Hijacking (CRITICAL)

Examines file association handlers for executable files:
- `SOFTWARE\Classes\exefile\shell\open\command` (both HKLM and HKCU)
- `SOFTWARE\Classes\comfile\shell\open\command` (both HKLM and HKCU)

This is Sality's primary infection vector. The malware modifies how .exe and .com files are launched, injecting itself before the legitimate program runs. Normal value should be `"%1" %*`. Suspicious indicators:
- Multiple .exe references in the command
- Unexpected executable paths before the `%1` parameter

### 4. Suspicious Random Registry Keys

Scans for registry keys matching Sality's pattern: `HKCU\Software\{RandomChars}\{RandomNumbers}`

Detection uses multiple heuristics:
- **Dictionary Filtering**: Excludes 100+ known legitimate software vendors (Microsoft, Google, Adobe, etc.)
- **Shannon Entropy Analysis**: Calculates character distribution
  - Normal English text: 3.5-4.0 bits/character
  - Random strings: 4.2+ bits/character
- **Consonant-to-Vowel Ratio**: Random generators often produce consonant-heavy strings (>70%)
- **Numeric Subkeys**: Common Sality pattern uses all-numeric subkey names

### 5. DLL Injection Points

Checks for malicious DLL injection mechanisms:
- `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`
  - **AppInit_DLLs**: Lists DLLs loaded into every process
  - **LoadAppInit_DLLs**: Must be 1 for AppInit_DLLs to take effect

Sality may use this mechanism to inject malicious code into all running processes. Any non-empty AppInit_DLLs value warrants investigation.

### 6. Browser Hijacking

Examines Internet proxy settings for unauthorized modifications:
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings`
  - **ProxyEnable**: Should be 0 unless user configured a proxy
  - **ProxyServer**: Proxy server address if enabled

Malware may enable proxy settings to intercept web traffic or redirect users to malicious sites.

### 7. Security Settings Tampering

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

**System Tool Restrictions:**
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System` (both HKCU and HKLM)
  - `DisableTaskMgr = 1` (Task Manager disabled)
  - `DisableRegistryTools = 1` (Registry Editor disabled)

Sality disables these tools to prevent users from detecting and removing the infection.

### 8. SafeBoot Modifications

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
[*] Checking Winlogon Hijacking:
=================================

  Shell = explorer.exe (OK)
  Userinit = C:\Windows\system32\userinit.exe, (OK)

[*] Checking File Association Hijacking:
=========================================

Executable File Associations:
  [SOFTWARE\Classes\exefile\shell\open\command]: "%1" %*
  [SOFTWARE\Classes\comfile\shell\open\command]: "%1" %*

[*] Checking for Suspicious Random Keys:
=========================================

  No suspicious random keys detected.

[*] Checking DLL Injection Points:
===================================

AppInit_DLLs Mechanism:
  AppInit_DLLs = (empty)
  LoadAppInit_DLLs = 0 (disabled)

[*] Checking Security Settings Tampering:
==========================================

Security Center Settings:

System Policy Settings:

System Tool Restrictions:
```

#### Infected System

```
[*] Checking Winlogon Hijacking:
=================================

  [SUSPICIOUS] Userinit = C:\Windows\system32\userinit.exe,C:\malware\evil.exe
    Reason: Multiple executables detected

[*] Checking File Association Hijacking:
=========================================

Executable File Associations:
  [SUSPICIOUS] [SOFTWARE\Classes\exefile\shell\open\command]
    Value: C:\malware\sality.exe "%1" %*
    Reason: Multiple executables or unexpected pattern

[*] Checking for Suspicious Random Keys:
=========================================

[SUSPICIOUS] [HKCU\Software\Xjkwnfrb\19283746]
  Reason: Random-looking key name with numeric subkey
  Entropy: 4.58 (normal English: 3.5-4.0, random: 4.2+)
  value1 = RegValue(REG_SZ: C:\Users\...\malware.exe)

[*] Checking DLL Injection Points:
===================================

AppInit_DLLs Mechanism:
  [FOUND] AppInit_DLLs = C:\malware\inject.dll
  [ENABLED] LoadAppInit_DLLs = 1

[*] Checking Security Settings Tampering:
==========================================

Security Center Settings:
  [HIT] [SOFTWARE\Microsoft\Security Center]\AntiVirusDisableNotify = 1
  [HIT] [SOFTWARE\Microsoft\Security Center\Svc]\FirewallDisableNotify = 1

System Policy Settings:
  [HIT] [SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System]\EnableLUA = 0

System Tool Restrictions:
  [HIT] [Software\Microsoft\Windows\CurrentVersion\Policies\System]\DisableTaskMgr = 1
  [HIT] [Software\Microsoft\Windows\CurrentVersion\Policies\System]\DisableRegistryTools = 1
```

## Detection Methodology

This tool employs 8 comprehensive detection categories to identify Sality infections:

1. **Autorun Persistence** - Monitors 5 registry locations for unauthorized startup entries
2. **Winlogon Hijacking** - Validates Shell and Userinit values
3. **File Association Hijacking** - Critical check for .exe/.com handler modifications
4. **Random Registry Keys** - Multi-heuristic analysis (entropy, dictionary, patterns)
5. **DLL Injection** - Checks AppInit_DLLs mechanism
6. **Browser Hijacking** - Examines proxy settings
7. **Security Tampering** - 13+ checks for disabled security features
8. **SafeBoot Modifications** - Detects prevention of Safe Mode boot

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
