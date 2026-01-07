import os
import yara
import argparse

def scan_files(target_path, rule_file):
    try:
        rules = yara.compile(filepath=rule_file)
    except yara.SyntaxError as e:
        print(f"[-] YARA Compilation Error: {e}")
        return

    print(f"[*] Scanning {target_path} using full Luckyware ruleset...")

    for root, _, files in os.walk(target_path):
        for file in files:
            full_path = os.path.join(root, file)
            try:
                matches = rules.match(full_path)
                if matches:
                    for match in matches:
                        print(f"[!] MATCH: {match.rule} detected in {full_path}")
                        for s in match.strings:
                            print(f"    - Found: {s[2]}")
            except yara.Error:
                continue

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Luckyware YARA Scanner")
    parser.add_argument("path", help="Path to scan (e.g. C:\ )")
    parser.add_argument("--rules", default="rules/luckyware.yar", help="Path to .yar file")
    args = parser.parse_args()

    if os.path.exists(args.rules):
        scan_files(args.path, args.rules)
    else:
        print(f"[-] Rules file not found at {args.rules}")
