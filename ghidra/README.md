# Ghidra compiler specification for AOT binaries

## What's this?

The compiler specification is one of the language modules used in Ghidra to support the disassembly and analysis of a particular processor. Its purpose is to describe the ABI of the compiler that generates binaries.

Since the decompilation result is based on the ABI described in the compiler specification, the decompilation result will be poor if the appropriate compiler specification is not selected.

Mach-O AOT binaries used in Rosetta 2 has its own ABI. Therefore, if the AOT binary is analyzed using the AArch64 ABI compiler specification, the decompilation results will be poor :(

This directory contains the compiler specifications to properly decompile the Mach-O AOT binaries.

## Usage

- Copy `AARCH64_aot.cspec` to `$GHIDRA_HOME/Processors/AARCH64/data/languages`
- Open `$GHIDRA_HOME/Processors/AARCH64/data/languages/AARCH64.ldefs` and add `<compiler name="macOS AOT" spec="AARCH64_aot.cspec" id="macOS_aot">`
- Restart Ghidra
- When opening a Mach-O AOT binary, please select "Languages:" and choose "macOS AOT" (see the figures below)

![select_lang1](./assets/select_lang1.png)
![select_lang2](./assets/select_lang2.png)

## Tested

Ghidra 9.2.1 public
