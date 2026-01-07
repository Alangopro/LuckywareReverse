import os
import yara
import argparse
import re
import ctypes
import pefile

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_domains_from_yara(rule_file):
    domains = set()
    domain_pattern = re.compile(r'\$d\d+\s*=\s*"([^"]+)"')
    try:
        with open(rule_file, "r") as f:
            for line in f:
                match = domain_pattern.search(line)
                if match:
                    domains.add(match.group(1))
    except:
        pass
    return list(domains)

def block_domains(domains):
    if not is_admin():
        print("[-] Admin required to block domains.")
        return
    
    hosts_path = r"C:\Windows\System32\drivers\etc\hosts"
    try:
        with open(hosts_path, "r") as f:
            content = f.read()
        
        with open(hosts_path, "a") as f:
            for d in domains:
                if d not in content and not re.match(r"^\d{1,3}\.", d):
                    f.write(f"\n0.0.0.0 {d}")
                    print(f"    [+] Blocked: {d}")
    except Exception as e:
        print(f"[-] HOSTS error: {e}")

def is_temp_location(file_path):
    path_lower = file_path.lower()
    temp_paths = ['\\temp\\', '\\appdata\\local\\temp\\', '\\appdata\\roaming\\', '\\appdata\\local\\']
    return any(p in path_lower for p in temp_paths)

def is_suspicious_temp_filename(filename):
    pattern = r'^[A-Z]{2,3}\d{10,13}(\.exe)?$'
    return re.match(pattern, filename) is not None

def has_malicious_rcd_sections(file_path):
    try:
        pe = pefile.PE(file_path)
        malicious_sections = []
        all_sections = []
        
        for section in pe.sections:
            section_name = section.Name.decode().strip('\x00')
            all_sections.append(section_name)
            if section_name.startswith('.rcd') and section_name != '.rcdata':
                entropy = section.get_entropy()
                is_executable = bool(section.Characteristics & 0x20000000)
                
                malicious_sections.append({
                    'name': section_name,
                    'entropy': entropy,
                    'executable': is_executable
                })
        
        pe.close()
        
        if malicious_sections:
            details = ", ".join([f"{s['name']} (entropy: {s['entropy']:.2f}, exec: {s['executable']})" for s in malicious_sections])
            return True, details, all_sections
        
        return False, None, all_sections
        
    except Exception as e:
        return False, None, []

def patch_pe_characteristics(file_path):
    try:
        pe = pefile.PE(file_path)
        modified = False
        
        for section in pe.sections:
            section_name = section.Name.decode().strip('\x00')
            if section_name.startswith(".rcd") and section_name != ".rcdata":
                if section.Characteristics & 0x20000000:
                    print(f"    [!] Removing execute flag from: {section_name}")
                    section.Characteristics &= ~0x20000000
                    modified = True
        
        if modified:
            pe.write(file_path)
            print(f"    [+] PATCHED: {file_path}")
        
        pe.close()
        
    except Exception as e:
        print(f"    [-] Patch Error: {e}")

def wipe_artifact(file_path):
    try:
        size = os.path.getsize(file_path)
        with open(file_path, "wb") as f:
            f.write(b"\x00" * size)
        print(f"    [!] WIPED: {file_path}")
    except Exception as e:
        print(f"    [-] Wipe Error: {e}")

def scan_temp_directories(auto_remove=False, debug=False):
    print(f"\n[+] Scanning Temp/AppData for suspicious filenames...")
    temp_dirs = []
    if os.environ.get('TEMP'):
        temp_dirs.append(os.environ['TEMP'])
    if os.environ.get('TMP'):
        temp_dirs.append(os.environ['TMP'])
    if os.environ.get('LOCALAPPDATA'):
        temp_dirs.append(os.path.join(os.environ['LOCALAPPDATA'], 'Temp'))
    temp_count = 0
    for temp_dir in temp_dirs:
        if not os.path.exists(temp_dir):
            continue
        if debug:
            print(f"[DEBUG] Scanning temp directory: {temp_dir}")
        try:
            for file in os.listdir(temp_dir):
                full_path = os.path.join(temp_dir, file)
                if os.path.isdir(full_path):
                    continue
                if is_suspicious_temp_filename(file):
                    if debug:
                        print(f"[DEBUG] Found suspicious temp file: {full_path}")
                    
                    print(f"\n[!] Luckyware_TempFile: {full_path}")
                    print(f"    [CONFIRMED] Matches Luckyware temp file naming pattern")
                    temp_count += 1
                    if auto_remove:
                        wipe_artifact(full_path)
        except Exception as e:
            if debug:
                print(f"[DEBUG] Error scanning {temp_dir}: {e}")
    print(f"[+] Temp scan complete: {temp_count} suspicious temp files found")
    return temp_count

def scan_files(target_path, rule_file, auto_remove=False, patch_pe=False, debug=False):
    try:
        rules = yara.compile(filepath=rule_file)
        print(f"[+] YARA rules loaded from: {rule_file}")
        print(f"[+] Starting scan of: {target_path}")
        print(f"[+] Scanning only .exe, .dll, .suo, .vcxproj files")
        if debug:
            print(f"[+] Debug mode enabled")
    except Exception as e:
        print(f"[-] YARA Error: {e}")
        return
    
    file_count = 0
    match_count = 0
    false_positive_count = 0
    yara_match_count = 0
    skipped_count = 0
    target_extensions = {'.exe', '.dll', '.suo', '.vcxproj'}
    
    for root, _, files in os.walk(target_path):
        for file in files:
            full_path = os.path.join(root, file)
            file_ext = os.path.splitext(file)[1].lower()
            if file_ext not in target_extensions:
                skipped_count += 1
                continue
            file_count += 1
            is_pe = file_ext in {'.exe', '.dll'}
            
            if file_count % 50 == 0:
                print(f"[*] Scanned {file_count} files ({skipped_count} skipped), {yara_match_count} YARA hits, {match_count} threats, {false_positive_count} FP...", end='\r')
            
            try:
                matches = rules.match(full_path)
                if matches:
                    yara_match_count += 1
                    if debug:
                        print(f"\n[DEBUG] YARA matched: {full_path}")
                        print(f"[DEBUG] Rules triggered: {[m.rule for m in matches]}")
                        print(f"[DEBUG] Is PE: {is_pe}")
                    
                    if is_pe:
                        has_malicious, reason, sections = has_malicious_rcd_sections(full_path)
                        
                        if debug:
                            print(f"[DEBUG] Checking sections: {sections}")
                            print(f"[DEBUG] Has malicious .rcdXXX: {has_malicious}")
                            if has_malicious:
                                print(f"[DEBUG] Malicious details: {reason}")
                        if has_malicious:
                            for match in matches:
                                print(f"\n[!] {match.rule}: {full_path}")
                            print(f"    [CONFIRMED INFECTION] Malicious sections: {reason}")
                            match_count += 1
                            
                            if patch_pe:
                                patch_pe_characteristics(full_path)
                        else:
                            false_positive_count += 1
                            if debug:
                                print(f"[FP] File has suspicious strings but no .rcdXXX sections")
                                print(f"     Sections found: {sections}")
                    else:
                        for match in matches:
                            print(f"\n[!] {match.rule}: {full_path}")
                        match_count += 1
                        if auto_remove:
                            if any(x in match.rule for match in matches for x in ["SUO", "VCXPROJ"]):
                                wipe_artifact(full_path)
                            
            except Exception as e:
                if debug:
                    print(f"\n[DEBUG] Error scanning {full_path}: {e}")
                continue
    
    print(f"\n[+] File scan complete!")
    print(f"    Relevant files scanned: {file_count}")
    print(f"    Files skipped: {skipped_count}")
    print(f"    YARA string matches: {yara_match_count}")
    print(f"    Confirmed infections: {match_count}")
    print(f"    False positives filtered: {false_positive_count}")
    temp_count = scan_temp_directories(auto_remove, debug)
    
    print(f"\n[+] TOTAL THREATS FOUND: {match_count + temp_count}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Luckyware Scanner")
    parser.add_argument("path", help="Target path")
    parser.add_argument("--rules", default="rules/luckyware.yar", help="YARA file")
    parser.add_argument("--block", action="store_true", help="Block C2 domains in HOSTS")
    parser.add_argument("--remove", action="store_true", help="Wipe artifacts")
    parser.add_argument("--patch-pe", action="store_true", help="Patch malicious .rcd sections")
    parser.add_argument("--debug", action="store_true", help="Enable debug output")
    
    args = parser.parse_args()
    
    if os.path.exists(args.rules):
        if args.block:
            block_domains(get_domains_from_yara(args.rules))
        scan_files(args.path, args.rules, args.remove, args.patch_pe, args.debug)
    else:
        print("[-] Rules file not found")
