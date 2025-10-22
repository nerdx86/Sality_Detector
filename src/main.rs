use winreg::enums::*;
use winreg::RegKey;
use regex::Regex;

fn main() {
    println!("Sality Malware Detector");
    println!("======================\n");

    // Display autorun locations
    display_autorun_keys();

    // Check for random subkeys under HKCU\Software
    check_random_software_keys();

    // Check security center tampering
    check_security_tampering();

    // Check for SafeBoot modifications
    check_safeboot_modifications();

    println!("\nScan complete.");
}

fn display_autorun_keys() {
    println!("[*] Checking Autorun Locations:");
    println!("================================\n");

    // HKCU Run
    println!("[HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]");
    display_all_values(&RegKey::predef(HKEY_CURRENT_USER),
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    println!();

    // HKLM Run
    println!("[HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]");
    display_all_values(&RegKey::predef(HKEY_LOCAL_MACHINE),
                      "Software\\Microsoft\\Windows\\CurrentVersion\\Run");
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
            // Pattern: random characters with random numbers subkey
            let key_pattern = Regex::new(r"^[a-zA-Z]{8,}$").unwrap();

            for key_name in software_key.enum_keys().filter_map(|x| x.ok()) {
                if key_pattern.is_match(&key_name) {
                    // Check if it has numeric subkeys
                    if let Ok(subkey) = software_key.open_subkey(&key_name) {
                        let number_pattern = Regex::new(r"^\d+$").unwrap();
                        for subkey_name in subkey.enum_keys().filter_map(|x| x.ok()) {
                            if number_pattern.is_match(&subkey_name) {
                                println!("[HKCU\\Software\\{}\\{}]", key_name, subkey_name);
                                let path = format!("Software\\{}\\{}", key_name, subkey_name);
                                display_all_values(&hkcu, &path);
                                println!();
                            }
                        }
                    }
                }
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
