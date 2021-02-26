# AOT Shared Cache Extractor

This script shows the contents of the AOT shared cache file (`/System/Library/dyld/aot_shared_cache`).

## What is AOT shared cache file? Why did I create this tool?

AOT shared cache is a combined AOT cache file to improve the performance of x64 emulation process initialization.

Its mechanism is similar to the dyld\_shared\_cache; when a new process is launched, Rosetta 2 runtime tries to look for AOT files of the required libraries from AOT shared cache. If found, the references to those contents are added to the Rosetta 2 runtime, and the loading process of AOT files is skipped.

AOT shared cache file is also undocumented like the dyld\_shared\_cache. Therefore, I reverse-engineered the structure of AOT shared cache, and write a simple python script to show the contents of AOT shared cache.

## How to use?

Before use this script, you need to install [poetry](https://github.com/python-poetry/poetry) to resolve its dependencies.
After that, you can install its dependencies as follows.

```
$ poetry shell
$ poetry update
```

Then, you can run this script and show the contents of the AOT shared cache file (`/System/Library/dyld/aot_shared_cache`).

```
$ python main.py /path/to/aot_shared_cache
AotCacheHeader:
        magic: 0x6568636143746f41
        field_0x8: 0x901e87ff163d262d
        field_0x10: 0xd530e2b9dd65e280
        uuid: ['0xac30dd6830a6b1e2', '0xda54b118c06a36a0']
        version: ['0xeeb5da8f5d78c616', '0xed2c96c23df23524', '0x51d12aea4260e7a2', '0xbf5873bbc58776']
        offset_to_codesig: 0x9a3fc000
        size_of_codesig: 0x134800b
        n_entries: 0x784
        offset_to_metadata_seg: 0x4000
        mapping:
        AotCacheMappingInfo:
                address: 0x0
                size: 0x106e0000
                file_offset: 0x0
                init_prot: 0x1
                max_prot: 0x1
        AotCacheMappingInfo:
                address: 0x106e0000
                size: 0xa58000
                file_offset: 0x0
                init_prot: 0x3
                max_prot: 0x3
        AotCacheMappingInfo:
                address: 0x11138000
                size: 0x89d1c000
                file_offset: 0x106e0000
                init_prot: 0x85
                max_prot: 0x85

metadata segment starts from 0x4000
number of entries is 1924
CodeFragmentMetaData:
        type: 0x1
        offset_to_path_name: 0x0
        offset_to_x64_code: 0x0
        size_of_x64_code: 0x0
        offset_to_arm64_code: 0x0
...
```

## Notes about [`aot_mapped_module_names`](./aot_mapped_module_names) file

[`aot_mapped_module_names`](./aot_mapped_module_names) contains the list of module names in the AOT shared cache file for macOS Bug Sur version 11.1.
The reason for providing this file is that aot\_shared\_cache does not include a list of module name information.

The information in the module name may depend on the version of macOS.

If you want to create `aot_mapped_module_names` for your environment, you can create it by enabling the Rosetta 2 `runtime` debugging feature (`ROSETTA_PRINT_SEGMENTS`). For more details, I will explain it in the article.

