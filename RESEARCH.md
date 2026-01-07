# Luckyware Technical Research

## XOR Configuration Decryption
The Luckyware RAT encrypts its C2 domains and configuration strings using a simple XOR algorithms. 
**Key:** `NtExploreProcess`

## Dropper Filename Generation
The malware generates its payload names dynamically to evade basic signature detection.
It uses the C++ `chrono` library:
`chrono::system_clock::now().time_since_epoch().count()`
This results in filenames starting with a 2-3 character prefix (e.g., BK, TX) followed by a 10-13 digit millisecond timestamp.

## Persistence Mechanisms
1. **SDK Poisoning:** Injects `namespace VccLibaries` into standard Windows headers.
2. **SUO Hijacking:** Replaces the binary `.suo` file in the `.vs` folder to execute code upon project load.
3. **PE Appending:** Injects a new section (usually `.rcd` + ID) and redirects the Entry Point.

There are a lot more things it does that i did not cover in this repository to save time.
