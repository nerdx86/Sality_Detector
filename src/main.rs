use winreg::enums::*;
use winreg::RegKey;
use regex::Regex;
use std::collections::HashSet;
use lazy_static::lazy_static;

lazy_static! {
    static ref DICTIONARY: HashSet<&'static str> = {
        let mut set = HashSet::new();
        // Common English words and legitimate software vendors
        let words = [
            "microsoft", "windows", "google", "chrome", "mozilla", "firefox",
            "adobe", "apple", "intel", "nvidia", "amd", "realtek", "dell",
            "lenovo", "hp", "asus", "samsung", "sony", "lg", "toshiba",
            "oracle", "java", "python", "node", "github", "docker", "steam",
            "spotify", "slack", "zoom", "skype", "teams", "outlook", "office",
            "visual", "studio", "code", "vmware", "virtualbox", "winrar",
            "classes", "clients", "policies", "wow6432node", "installer",
            "uninstall", "classes", "current", "version", "run", "services",
            "application", "program", "system", "software", "hardware",
            "network", "internet", "security", "antivirus", "firewall",
            "backup", "update", "download", "install", "registry", "control",
            "user", "admin", "local", "machine", "config", "settings",
            "anthropic", "claude", "nvidia", "geforce", "experience",
            "rockstar", "games", "epic", "valve", "origin", "uplay",
            "discord", "telegram", "whatsapp", "signal", "dropbox", "onedrive",
            "icloud", "creative", "cloud", "acrobat", "reader", "flash",
            "shockwave", "quicktime", "winamp", "vlc", "media", "player",
            "defender", "kaspersky", "avast", "avg", "malwarebytes", "norton",
            "mcafee", "bitdefender", "eset", "sophos", "trend", "micro"
        ];
        for word in &words {
            set.insert(*word);
        }
        set
    };
}

fn calculate_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }

    let mut char_counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    let len = s.len() as f32;

    for c in s.chars() {
        *char_counts.entry(c.to_ascii_lowercase()).or_insert(0) += 1;
    }

    let mut entropy = 0.0;
    for count in char_counts.values() {
        let probability = *count as f32 / len;
        entropy -= probability * probability.log2();
    }

    entropy
}

fn is_likely_random(key_name: &str) -> bool {
    let lower = key_name.to_lowercase();

    // Exact dictionary match
    if DICTIONARY.contains(lower.as_str()) {
        return false;
    }

    // Check if it's a combination of dictionary words (camelCase, etc.)
    // Split by common patterns
    let parts: Vec<&str> = lower.split(|c: char| !c.is_alphabetic()).collect();
    let all_parts_valid = parts.iter()
        .filter(|p| !p.is_empty())
        .all(|p| p.len() < 4 || DICTIONARY.contains(p));

    if all_parts_valid && !parts.is_empty() {
        return false;
    }

    // Additional heuristics for random strings
    let alpha_only: String = key_name.chars().filter(|c| c.is_alphabetic()).collect();

    // Must have at least some alphabetic characters
    if alpha_only.len() < 6 {
        return false;
    }

    // Calculate Shannon entropy
    let entropy = calculate_entropy(&alpha_only);

    // High entropy indicates random/evenly distributed characters
    // English text typically has entropy around 3.5-4.0
    // Random strings have entropy around 4.5-5.0+ (for mixed case)
    let high_entropy = entropy > 4.2;

    // Check for suspicious patterns:
    // 1. High consonant-to-vowel ratio (random strings often lack vowels)
    let vowels = "aeiouAEIOU";
    let vowel_count = alpha_only.chars().filter(|c| vowels.contains(*c)).count();
    let consonant_count = alpha_only.len() - vowel_count;

    // If more than 70% consonants in a 6+ char string, likely random
    let high_consonant_ratio = alpha_only.len() >= 6
        && (consonant_count as f32 / alpha_only.len() as f32) > 0.7;

    // 2. No recognizable dictionary words as substrings (3+ chars)
    let has_word_substring = DICTIONARY.iter().any(|word| {
        word.len() >= 4 && lower.contains(word)
    });

    let no_dictionary_substrings = !has_word_substring && alpha_only.len() >= 8;

    // Flag as suspicious if multiple indicators present
    if high_entropy && (high_consonant_ratio || no_dictionary_substrings) {
        return true;
    }

    if high_consonant_ratio && no_dictionary_substrings {
        return true;
    }

    false
}

fn check_file_associations() {
    println!("[*] Checking File Association Hijacking:");
    println!("=========================================\n");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    println!("Executable File Associations:");
    check_command_value(&hklm, "SOFTWARE\\Classes\\exefile\\shell\\open\\command", "");
    check_command_value(&hkcu, "SOFTWARE\\Classes\\exefile\\shell\\open\\command", "");
    check_command_value(&hklm, "SOFTWARE\\Classes\\comfile\\shell\\open\\command", "");
    check_command_value(&hkcu, "SOFTWARE\\Classes\\comfile\\shell\\open\\command", "");

    println!();
}

fn check_command_value(hive: &RegKey, path: &str, value_name: &str) {
    match hive.open_subkey(path) {
        Ok(key) => {
            match key.get_value::<String, _>(value_name) {
                Ok(value) => {
                    let lower = value.to_lowercase();
                    // Normal: '"%1" %*' or similar
                    // Suspicious: Multiple .exe references or unexpected patterns
                    let exe_count = lower.matches(".exe").count();
                    let has_suspicious_pattern = (lower.contains("%1") && !value.starts_with("\"")) ||
                                                 lower.split_whitespace()
                                                      .filter(|s| s.ends_with(".exe\"") || s.ends_with(".exe"))
                                                      .count() > 1;

                    if exe_count > 1 || has_suspicious_pattern {
                        println!("  [SUSPICIOUS] [{}]", path);
                        println!("    Value: {}", value);
                        println!("    Reason: Multiple executables or unexpected pattern");
                    } else {
                        println!("  [{}]: {}", path, value);
                    }
                }
                Err(_) => {
                    println!("  [{}]: (not set)", path);
                }
            }
        }
        Err(_) => {
            println!("  [{}]: (key not found)", path);
        }
    }
}

fn check_winlogon() {
    println!("[*] Checking Winlogon Hijacking:");
    println!("=================================\n");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";

    match hklm.open_subkey(path) {
        Ok(key) => {
            // Shell should be "explorer.exe"
            if let Ok(shell) = key.get_value::<String, _>("Shell") {
                let normalized = shell.trim().to_lowercase();
                if normalized.is_empty() || normalized == "explorer.exe" {
                    println!("  Shell = {} (OK)", shell);
                } else {
                    println!("  [SUSPICIOUS] Shell = {}", shell);
                    println!("    Expected: explorer.exe");
                }
            } else {
                println!("  Shell = (not set - OK)");
            }

            // Userinit should be "C:\\Windows\\system32\\userinit.exe,"
            if let Ok(userinit) = key.get_value::<String, _>("Userinit") {
                let normalized = userinit.to_lowercase().replace("\\\\", "\\");
                let exe_count = normalized.matches(".exe").count();

                if normalized.contains("system32\\userinit.exe") && exe_count == 1 {
                    println!("  Userinit = {} (OK)", userinit);
                } else if exe_count > 1 {
                    println!("  [SUSPICIOUS] Userinit = {}", userinit);
                    println!("    Reason: Multiple executables detected");
                } else if !normalized.contains("system32\\userinit.exe") {
                    println!("  [SUSPICIOUS] Userinit = {}", userinit);
                    println!("    Expected: C:\\Windows\\system32\\userinit.exe,");
                }
            } else {
                println!("  Userinit = (not set)");
            }
        }
        Err(e) => println!("  Error accessing Winlogon: {}", e),
    }

    println!();
}

fn check_dll_injection() {
    println!("[*] Checking DLL Injection Points:");
    println!("===================================\n");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let path = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";

    println!("AppInit_DLLs Mechanism:");
    match hklm.open_subkey(path) {
        Ok(key) => {
            if let Ok(dlls) = key.get_value::<String, _>("AppInit_DLLs") {
                if !dlls.trim().is_empty() {
                    println!("  [FOUND] AppInit_DLLs = {}", dlls);
                } else {
                    println!("  AppInit_DLLs = (empty)");
                }
            } else {
                println!("  AppInit_DLLs = (not set)");
            }

            if let Ok(load) = key.get_value::<u32, _>("LoadAppInit_DLLs") {
                if load == 1 {
                    println!("  [ENABLED] LoadAppInit_DLLs = 1");
                } else {
                    println!("  LoadAppInit_DLLs = 0 (disabled)");
                }
            }
        }
        Err(e) => println!("  Error accessing Windows key: {}", e),
    }

    println!();
}

fn check_browser_hijacking() {
    println!("[*] Checking Browser Hijacking:");
    println!("================================\n");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let path = "Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings";

    println!("Internet Proxy Settings:");
    match hkcu.open_subkey(path) {
        Ok(key) => {
            if let Ok(enabled) = key.get_value::<u32, _>("ProxyEnable") {
                if enabled == 1 {
                    println!("  [FOUND] ProxyEnable = 1");
                    if let Ok(server) = key.get_value::<String, _>("ProxyServer") {
                        println!("  [FOUND] ProxyServer = {}", server);
                    }
                } else {
                    println!("  ProxyEnable = 0 (disabled)");
                }
            } else {
                println!("  ProxyEnable = (not set)");
            }
        }
        Err(e) => println!("  Error accessing Internet Settings: {}", e),
    }

    println!();
}

fn main() {
    println!("Sality Malware Detector");
    println!("======================\n");

    // Display autorun locations
    display_autorun_keys();

    // Check Winlogon hijacking
    check_winlogon();

    // Check file association hijacking
    check_file_associations();

    // Check for random subkeys under HKCU\Software
    check_random_software_keys();

    // Check DLL injection points
    check_dll_injection();

    // Check browser hijacking
    check_browser_hijacking();

    // Check security center tampering
    check_security_tampering();

    // Check for SafeBoot modifications
    check_safeboot_modifications();

    println!("\nScan complete.");
}

fn display_autorun_keys() {
    println!("[*] Checking Autorun Locations:");
    println!("================================\n");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    // HKCU Run
    println!("[HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]");
    display_all_values(&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    println!();

    // HKLM Run
    println!("[HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]");
    display_all_values(&hklm, "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    println!();

    // HKCU RunOnce
    println!("[HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce]");
    display_all_values(&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    println!();

    // HKLM RunOnce
    println!("[HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce]");
    display_all_values(&hklm, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce");
    println!();

    // SharedTaskScheduler
    println!("[HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler]");
    display_all_values(&hklm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\SharedTaskScheduler");
    println!();
}

fn display_all_values(hive: &RegKey, path: &str) {
    match hive.open_subkey(path) {
        Ok(key) => {
            let mut found_any = false;
            for (name, value) in key.enum_values()
                .filter_map(|x| x.ok()) {
                found_any = true;
                println!("  {} = {:?}", name, value);
            }
            if !found_any {
                println!("  (No entries found)");
            }
        }
        Err(e) => {
            println!("  Error reading key: {}", e);
        }
    }
}

fn check_random_software_keys() {
    println!("[*] Checking for Suspicious Random Keys:");
    println!("=========================================\n");

    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    match hkcu.open_subkey("Software") {
        Ok(software_key) => {
            let number_pattern = Regex::new(r"^\d+$").unwrap();
            let mut found_suspicious = false;

            for key_name in software_key.enum_keys().filter_map(|x| x.ok()) {
                // Use dictionary-based detection
                if is_likely_random(&key_name) {
                    // Check if it has numeric subkeys (common Sality pattern)
                    if let Ok(subkey) = software_key.open_subkey(&key_name) {
                        for subkey_name in subkey.enum_keys().filter_map(|x| x.ok()) {
                            if number_pattern.is_match(&subkey_name) {
                                found_suspicious = true;
                                let alpha_only: String = key_name.chars()
                                    .filter(|c| c.is_alphabetic())
                                    .collect();
                                let entropy = calculate_entropy(&alpha_only);

                                println!("[SUSPICIOUS] [HKCU\\Software\\{}\\{}]", key_name, subkey_name);
                                println!("  Reason: Random-looking key name with numeric subkey");
                                println!("  Entropy: {:.2} (normal English: 3.5-4.0, random: 4.2+)", entropy);
                                let path = format!("Software\\{}\\{}", key_name, subkey_name);
                                display_all_values(&hkcu, &path);
                                println!();
                            }
                        }
                    }
                }
            }

            if !found_suspicious {
                println!("  No suspicious random keys detected.\n");
            }
        }
        Err(e) => {
            println!("  Error enumerating Software key: {}", e);
        }
    }
}

fn check_security_tampering() {
    println!("[*] Checking Security Settings Tampering:");
    println!("==========================================\n");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);

    // Security Center checks
    println!("Security Center Settings:");
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center",
                     "AntiVirusOverride", 1);
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center",
                     "AntiVirusDisableNotify", 1);

    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center\\Svc",
                     "AntiVirusDisableNotify", 1);
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center\\Svc",
                     "FirewallDisableNotify", 1);
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center\\Svc",
                     "FirewallOverride", 1);
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center\\Svc",
                     "UpdatesDisableNotify", 1);
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Security Center\\Svc",
                     "UacDisableNotify", 1);

    println!("\nSystem Policy Settings:");
    check_dword_value(&hklm, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                     "EnableLUA", 0);

    println!("\nFirewall Settings:");
    check_dword_value(&hklm, "SYSTEM\\ControlSet001\\services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                     "EnableFirewall", 0);
    check_dword_value(&hklm, "SYSTEM\\ControlSet001\\services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                     "DoNotAllowExceptions", 0);
    check_dword_value(&hklm, "SYSTEM\\ControlSet001\\services\\SharedAccess\\Parameters\\FirewallPolicy\\StandardProfile",
                     "DisableNotifications", 1);

    println!("\nExplorer Settings (Hidden Files):");
    check_dword_value(&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                     "Hidden", 2);
    check_dword_value(&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced",
                     "ShowSuperHidden", 0);

    println!("\nSystem Tool Restrictions:");
    check_dword_value(&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                     "DisableTaskMgr", 1);
    check_dword_value(&hkcu, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                     "DisableRegistryTools", 1);
    check_dword_value(&hklm, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                     "DisableTaskMgr", 1);
    check_dword_value(&hklm, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                     "DisableRegistryTools", 1);

    println!();
}

fn check_dword_value(hive: &RegKey, path: &str, value_name: &str, expected: u32) {
    match hive.open_subkey(path) {
        Ok(key) => {
            match key.get_value::<u32, _>(value_name) {
                Ok(actual) => {
                    if actual == expected {
                        println!("  [HIT] [{}]\\{} = {}", path, value_name, actual);
                    }
                }
                Err(_) => {
                    // Value doesn't exist or wrong type - not a hit
                }
            }
        }
        Err(_) => {
            // Key doesn't exist - not a hit
        }
    }
}

fn check_safeboot_modifications() {
    println!("[*] Checking SafeBoot Modifications:");
    println!("====================================\n");

    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);

    match hklm.open_subkey("SYSTEM\\CurrentControlSet\\Control\\SafeBoot") {
        Ok(safeboot_key) => {
            println!("[HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot]");

            // Enumerate all subkeys
            for subkey_name in safeboot_key.enum_keys().filter_map(|x| x.ok()) {
                println!("  Subkey found: {}", subkey_name);

                // Recursively check for suspicious modifications
                let path = format!("SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\{}", subkey_name);
                if let Ok(subkey) = hklm.open_subkey(&path) {
                    check_safeboot_recursive(&subkey, &path, 1);
                }
            }
        }
        Err(e) => {
            println!("  No SafeBoot key found or error: {}", e);
        }
    }

    println!();
}

fn check_safeboot_recursive(key: &RegKey, path: &str, depth: usize) {
    if depth > 5 {
        return; // Prevent infinite recursion
    }

    let indent = "  ".repeat(depth);

    // Check all values in this key
    for (name, value) in key.enum_values().filter_map(|x| x.ok()) {
        println!("{}  {} = {:?}", indent, name, value);
    }

    // Recurse into subkeys
    for subkey_name in key.enum_keys().filter_map(|x| x.ok()) {
        println!("{}  [{}]", indent, subkey_name);
        if let Ok(subkey) = key.open_subkey(&subkey_name) {
            let new_path = format!("{}\\{}", path, subkey_name);
            check_safeboot_recursive(&subkey, &new_path, depth + 1);
        }
    }
}
