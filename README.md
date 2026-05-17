> [!NOTE]
> There is a more complete implementation of this scanner available at
> https://github.com/kubixrq-arch/Luckyware-Cleaner it handles executable file analysis more accurately (yes i am aware that its vibe coded but it handles PE files correctly).

# LuckywareReverse

A toolkit for detecting, flagging, and removing Luckyware infections from binaries, source code, and related artifacts.

![Python](https://img.shields.io/badge/Python-3.12%2B-%23000000?logo=python&logoColor=pink&labelColor=000000&color=000000&style=for-the-badge)
![License: MIT](https://img.shields.io/badge/License-MIT-%23000000.svg?logo=spdx&logoColor=pink&labelColor=000000&color=000000&style=for-the-badge)
![Code size](https://img.shields.io/github/languages/code-size/runtimefailure/LuckywareReverse?logo=github&labelColor=000000&logoColor=pink&color=000000&style=for-the-badge)
![GitHub stars](https://img.shields.io/github/stars/runtimefailure/LuckywareReverse?logo=github&logoColor=pink&labelColor=000000&color=000000&style=for-the-badge)
![GitHub forks](https://img.shields.io/github/forks/runtimefailure/LuckywareReverse?logo=github&logoColor=pink&labelColor=000000&color=000000&style=for-the-badge)
![GitHub issues](https://img.shields.io/github/issues/runtimefailure/LuckywareReverse?logo=github&logoColor=pink&labelColor=000000&color=000000&style=for-the-badge)
[![Discord](https://img.shields.io/badge/Discord-%23000000.svg?style=for-the-badge&logo=discord&logoColor=pink)](https://dc.queenmc.pl/)
[![YouTube](https://img.shields.io/badge/YouTube-%23000000.svg?style=for-the-badge&logo=YouTube&logoColor=pink)](https://slat.cc/svchost)
[![Telegram](https://img.shields.io/badge/Telegram-%23000000?style=for-the-badge&logo=telegram&logoColor=pink)](https://slat.cc/svchost)

---

## Features

| Feature | Description |
| :--- | :--- |
| PE Section Analysis | Detects malicious `.rcd` sections in executables |
| Chrono-Logic Detection | Flags droppers via millisecond timestamp naming |
| SDK Integrity Check | Scans Windows Kits for the VccLibaries backdoor |
| SUO/VCXPROJ Cleaner | Identifies and nulls malicious Visual Studio project artifacts |
| YARA Integration | Full ruleset covering C2 domains and XOR indicators |
| Automatic Blocking | Syncs extracted C2 domains directly to the system hosts file |

---

## Technical Findings

This project is based on reverse engineering of the Luckyware leak. Key findings:

- **Domain decryption** C2 domains are XOR-encrypted with the key `NtExploreProcess`
- **Dropper naming** Droppers generate filenames using `chrono::system_clock::now()` in milliseconds
- **Infection vector** Executable code is appended to resource sections; `.suo` files are replaced with malicious versions

---

## Usage

```bash
python LuckyScanner.py <target_path> [options]
```

| Option | Description |
| :--- | :--- |
| `<path>` | Target drive or folder to scan (e.g. `C:\` or `D:`) |
| `--rules` | Path to the YARA rules file (default: `rules/luckyware.yar`) |
| `--block` | Sync YARA-extracted C2 domains to the Windows HOSTS file |
| `--remove` | Wipe infected Temp/SUO/VCXPROJ files with null bytes |
| `--patch-pe` | Clear execute bits on malicious PE sections |

---

## Removal Instructions

1. **Block C2 communication** Run with `--block` to sync extracted domains to `C:\Windows\System32\drivers\etc\hosts`. This prevents the loader from reaching its C2 servers.

2. **Scan and clean** Run `src/LuckyScanner.py` against the target system.
   - `--remove` nulls out malicious `.suo`, `.vcxproj`, and temp dropper files
   - `--patch-pe` clears the execute bits on infected PE sections, disabling the RAT entry point without corrupting the file

3. **Follow-up AV scan** Run a full scan with **Bitdefender Ultimate** (30-day trial is sufficient).
   - Enable all protection layers: Advanced Threat Control, Scan Execute, etc.
   - Bitdefender will detect the patched PE files and safely remove the malicious segments.

---

## Safety Warning & Disclaimer

This repository contains references to the Luckyware source code leak for research purposes only.

- **Do not compile the leaked source.** It is infected with its own embedded RAT, delivered via `.vcxproj` and `.suo` file manipulation.
- This project is provided as-is for malware researchers. The author assumes no responsibility for damages resulting from misuse of these tools or the referenced source material.

If you have access to a copy of the source, you can verify whether it has been further tampered with at https://luckywarescanner.dlazyje.workers.dev/

---

## Contributing

Contributions are welcome. If you discover new C2 domains, infection methods, or YARA signatures, open a pull request.

This project is licensed under the MIT License. The referenced malware source code is a third-party leak and is not covered by this license.

[![Star History Chart](https://api.star-history.com/svg?repos=runtimefailure/LuckywareReverse&type=date&legend=top-left)](https://www.star-history.com/#runtimefailure/LuckywareReverse&type=date&legend=top-left)
