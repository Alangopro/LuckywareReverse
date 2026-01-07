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

def patch_pe_characteristics(file_path):
    """Optional: Flips the Execute bit to 0. Does NOT remove sections."""
    try:
        pe = pefile.PE(file_path)
        modified = False
        for section in pe.sections:
            section_name = section.Name.decode().strip('\x00')
            if section_name.startswith(".rcd") and (section.Characteristics & 0x20000000):
                print(f"    [!] Found Malicious Executable Section: {section_name}")
                section.Characteristics &= ~0x20000000
                modified = True
        
        if modified:
            pe.write(file_path)
            pe.close()
            print(f"    [+] PATCHED: {file_path} (Execute bit removed for Bitdefender scan)")
        else:
            pe.close()
    except Exception as e:
        print(f"    [-] PE Patch Error: {e}")

def wipe_artifact(file_path):
    """Optional: Wipes non-PE artifacts (SUO/VCXPROJ/Temp) with null bytes."""
    try:
        size = os.path.getsize(file_path)
        with open(file_path, "wb") as f:
            f.write(b"\x00" * size)
        print(f"    [!] WIPED: {file_path}")
    except Exception as e:
        print(f"    [-] Wipe Error: {e}")

def scan_files(target_path, rule_file, auto_remove=False, patch_pe=False):
    try:
        rules = yara.compile(filepath=rule_file)
    except Exception as e:
        print(f"[-] YARA Error: {e}")
        return

    print(f"[*] Scanning {target_path}...")
    for root, _, files in os.walk(target_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                matches = rules.match(full_path)
                if matches:
                    for match in matches:
                        print(f"[!] {match.rule}: {full_path}")
                        if auto_remove and any(x in match.rule for x in ["TempFile", "SUO", "VCXPROJ"]):
                            wipe_artifact(full_path)
                        
                        if patch_pe and "PE_Infection" in match.rule:
                            patch_pe_characteristics(full_path)
            except:
                continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Luckyware Master Tool")
    parser.add_argument("path", help="Target path")
    parser.add_argument("--rules", default="rules/luckyware.yar", help="YARA file")
    parser.add_argument("--block", action="store_true", help="Sync domains to HOSTS")
    parser.add_argument("--remove", action="store_true", help="OPTIONAL: Wipe Temp/Project artifacts")
    parser.add_argument("--patch-pe", action="store_true", help="OPTIONAL: Flip PE execute bits to 0")
    args = parser.parse_args()

    if os.path.exists(args.rules):
        if args.block:
            block_domains(get_domains_from_yara(args.rules))
        scan_files(args.path, args.rules, args.remove, args.patch_pe)
    else:
        print("[-] Rules missing.")
