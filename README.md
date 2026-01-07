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

1. **Block Network Communication:** Immediately block all C2 domains identified in the `rules/luckyware.yar` file. 
   * **Hosts File:** Redirect all identified domains to `0.0.0.0` in your Windows hosts file (`C:\Windows\System32\drivers\etc\hosts`) to prevent the loader from fetching payloads.
   * **Firewall:** Use third-party firewall software to block these addresses.

2. **Run Scanner:** Execute `src/LuckyScanner.py` to identify all infected artifacts, including SDK poisoning, malicious .suo files, and compromised project files.

3. **Bitdefender Clean:** Use **Bitdefender Ultimate** (the 30-day trial is sufficient). 
   * **Requirement:** You must enable **all protection options** (Advanced Threat Control, Scan Execute, etc.). 
   * This is necessary to successfully strip and remove the PE-based malware sections from infected executables that have been backdoored.


## Features

| Feature | Description |
| :--- | :--- |
| PE Section Analysis | Detects malicious executable .rcdata sections |
| Chrono-Logic Detection | Flags droppers via millisecond timestamp naming |
| SDK Integrity Check | Scans Windows Kits for the VccLibaries backdoor |
| SUO/VXPROJ Cleaner | Identifies and wipes malicious VS project hacks |
| YARA Integration | Full ruleset for C2 domains and XOR indicators |
| Automated Quarantine | Safely isolates infected artifacts for analysis |

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
| -d, --drive | Target drive or folder to scan (e.g., D:) |
| --yara | Run full YARA ruleset against memory and files |
| --clean-vs | Force-delete all .vs folders and .suo files |
| --verbose | Show detailed PE header offsets during scan |

## Safety Warning and Disclaimer

This repository contains sublinks to the Luckyware Source Code Leak for research purposes.

* DO NOT ATTEMPT TO COMPILE THE SOURCE.
* The source code itself is infected with its own RAT (found in .vcxproj and .suo files).
* This project is provided "as-is" for malware researchers. The author is not responsible for any damage caused by the misuse of these tools or the linked source.

## Contributing

Contributions are welcome. If you find new C2 domains or infection methods, please open a Pull Request.

This project is licensed under the MIT License. The linked malware source code is a third-party leak and is not covered by this license.
