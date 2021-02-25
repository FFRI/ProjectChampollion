# AOT Shared Cache Extractor

This script shows the contents in AOT shared cache file (`/System/Library/dyld/aot_shared_cache`).

## What is AOT shared cache file? Why did I create this tool?

AOT shared cache is a combined AOT cache file to improve the performance of x64 emulation process initialization.

Its mechanism is similar to the dyld\_shared\_cache; when a new process is launched, Rosetta 2 runtime tries to look for AOT files of the required libraries from AOT shared cache. If found, the references to those contents are added to the Rosetta 2 runtime, and the loading process of AOT files is skipped.

AOT shared cache file is also undocumented like the dyld\_shared\_cache. Therefore, I reverse-engineered the structure of AOT shared cache, and write a simple python script to show the contents of AOT shared cache.

## Notes about `aot_mapped_module_names` file

`aot_mapped_module_names` contains the list of module names in the AOT shared cache file for macOS Bug Sur version 11.1.
The reason for providing this file is that aot\_shared\_cache does not include a list of module name information.

The information in the module name may depend on the version of macOS.

If you want to create `aot_mapped_module_names` for your environment, you can create it by enabling the Rosetta 2 `runtime` debugging feature (`ROSETTA_PRINT_SEGMENTS`). For more details, I will explain it in the article.

