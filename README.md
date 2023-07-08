# CheatFighter
Extract threat intelligence from memory modifying game cheats through static binary analysis. CheatFighter is build atop of Ghidra for Android based games and IDA Pro for Windows game. The scripts folder contians all the different scripts used in CheatFighter. 

## Scripts
This folder contains all the scripts as used by CheatFighter. 
### Ghidra Scripts
CheatFighter is implemented as a post script for Ghidra. That is it is supposed to be run after Ghidra has run its initial analysis on the binary. The main script is CheatFighter.java whereas the others are for supporting functionality. 

### ELF Finder
This script searches for eligible ELF executables recursively to find cheats to be analyzed by CheatFighter.

### IDA Script
This script is a case study for windows games as implemented by using KERNEL32 APIs by MEMORY.DLL.


## Code Modifier
This code uses the ROSLYN Compiler to modify source code as proof-of-concept for automated client hardening. This specific example defends against our custom made cheat for San Andreas Unity as present in cheat_saunity.cpp.

## Cheat SAUnity
This is our custom made cheat for San Andreas Unity and the compiled version can be found as well as form of example. 

## MAG Translation
The MAG Translation is compiled and injected into the game after every Shared Object (SO) has been loaded to identify the data structures sitting at the addresses the cheat accesses. 

# Tutorial
1. Download Ghidra from https://ghidra-sre.org/
2. Import ELF (cheat_saunity)
3. Analyze ELF by Ghidra
4. Add the directory ghidra_scripts as source for script
5. Search for CheatFighter Script
6. Run CheatFighter!
