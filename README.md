<img width="272" height="704" alt="Gemini_Generated_Image_puupfvpuupfvpuup" src="https://github.com/user-attachments/assets/09c356a6-b8aa-4107-a0e6-21331fa54b8a" />
<img width="472" height="590" alt="image" src="https://github.com/user-attachments/assets/ad431362-acfa-4a7f-b1e1-badb9a0ebbdb" />

# LuckywareReverse

**Advanced Technical Analysis and Automated Removal Suite for the Luckyware RAT**

A professional-grade toolkit designed to detect, flag, and neutralize Luckyware infections across binaries, development environments, and persistence layers.

![Python](https://img.shields.io/badge/Python-3.12%2B-blue?logo=python&logoColor=white&style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)
![Code size](https://img.shields.io/github/languages/code-size/Alangopro/LuckywareReverse?style=for-the-badge)

![GitHub stars](https://img.shields.io/github/stars/Alangopro/LuckywareReverse?style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/Alangopro/LuckywareReverse?style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/Alangopro/LuckywareReverse?style=for-the-badge)

[![Discord](https://img.shields.io/badge/Discord-%235865F2.svg?style=for-the-badge&logo=discord&logoColor=white)](https://dc.queenmc.pl/)
[![YouTube](https://img.shields.io/badge/YouTube-%23FF0000.svg?style=for-the-badge&logo=YouTube&logoColor=white)](https://feds.lol/Kamerzystanasyt)
[![Telegram](https://img.shields.io/badge/Telegram-2CA5E0?style=for-the-badge&logo=telegram&logoColor=white)](https://feds.lol/Kamerzystanasyt)

## Removal Instructions

To fully purge this malware from your system, follow these steps:

1. **Block Network Communication:** Use the `--block` flag with the scanner to automatically sync YARA-extracted domains to your Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`). This prevents the loader from fetching further payloads.
   
2. **Run Scanner & Neutralize:** Execute `src/LuckyScanner.py` to identify artifacts.
   * Use `--remove` to wipe malicious .suo, .vcxproj, and temp files with null bytes.
   * Use `--patch-pe` to flip the Execute bits of malicious sections to 0. This disables the RAT's entry point without destroying the file structure.

3. **Bitdefender Clean:** Finally, run a scan with **Bitdefender Ultimate** (30-day trial works).
   * **Requirement:** Enable **all protection options** (Advanced Threat Control, Scan Execute, etc.).
   * Bitdefender will identify the neutralized/patched PE files and safely strip the malicious segments.

## Features

| Feature | Description |
| :--- | :--- |
| PE Section Analysis | Detects malicious executable .rcdata sections |
| Chrono-Logic Detection | Flags droppers via millisecond timestamp naming |
| SDK Integrity Check | Scans Windows Kits for the VccLibaries backdoor |
| SUO/VXPROJ Cleaner | Identifies and wipes malicious VS project hacks |
| YARA Integration | Full ruleset for C2 domains and XOR indicators |
| Automatic Blocking | Updates system hosts file directly from YARA rules |

## Technical Insights

This project is the result of deep reverse engineering of the Luckyware leak. Key findings include:
* Domain Decryption: Uses XOR with the key NtExploreProcess.
* File Naming: Droppers utilize chrono::system_clock::now() in milliseconds.
* Infection Vector: Appends executable code to resource sections and replaces .suo files.

## Usage

```bash
python LuckyScanner.py <target_path> [options]
```

| Option | Description |
| --- | --- |
| <path> | Target drive or folder to scan (e.g., C:\ or D:) |
| --rules | Path to the luckyware.yar file (Default: rules/luckyware.yar) |
| --block | Automatically sync YARA domains to Windows HOSTS file |
| --remove | OPTIONAL: Wipe infected Temp/SUO/VCXPROJ files with null bytes |
| --patch-pe | OPTIONAL: Flip Execute bits on malicious PE sections to 0 |

## Safety Warning and Disclaimer

This repository contains sublinks to the Luckyware Source Code Leak for research purposes.

* DO NOT ATTEMPT TO COMPILE THE SOURCE.
* The source code itself is infected with its own RAT (found in .vcxproj and .suo files).
* This project is provided "as-is" for malware researchers. The author is not responsible for any damage caused by the misuse of these tools or the linked source.

## Contributing

Contributions are welcome. If you find new C2 domains or infection methods, please open a Pull Request.

This project is licensed under the MIT License. The linked malware source code is a third-party leak and is not covered by this license.
