# Reverse-engineering Rosetta 2 part2: Analyzing other aspects of Rosetta 2 `runtime` and AOT shared cache files

date: 2021/3/4

author: Koh M. Nakagawa

## Introduction

In part2, I will discuss three features of the Rosetta 2 `runtime`:

- communicating with `oahd`
- loading and parsing AOT files to be mapped
- logging in debug mode

I will then introduce an AOT shared cache file, which plays a similar role to the `dyld_shared_cache`.

## Features of Rosetta 2 `runtime`

In the ["Roles of oahd and oahd-helper" section of part1](part1.md#roles-of-oahd-and-oahd-helper), I explained that `oahd` checks for AOT files and runs `oahd-helper` to create AOT files if needed.
However, the [logs of EventMonitor](./assets/event.jsonl) do not contain detailed information on how `oahd` obtains x86\_64 executables to be translated.
Moreover, we could not figure out how emulation process gets the AOT files required for the execution.
Such information was missing because we could not get some parts of the inter-process communication (IPC) through the Endpoint Security Framework.

In this section, I will discuss the inter-process communication between `oahd` and `runtime` to answer these questions.
Then, I will introduce `runtime`'s features of loading and parsing AOT files.
During analyzing the parsing logic of AOT files in `runtime`, I found a new Mach-O command called `LC_AOT_METADATA`.
So, I will mainly focus on the `LC_AOT_MEATADATA` command and its structure.

### Feature of Rosetta 2 `runtime`: communicating with `oahd`

`oahd` passes x86_64 executables and AOT files through inter-process communication with the Rosetta 2 `runtime`.
This is achieved by passing these file descriptors through Mach IPC via the following two undocumented system calls.

- `sys_fileport_makeport`
- `sys_fileport_makefd`

If you are not familiar with these system calls, you can find a brief description of these system calls [here](https://robert.sesek.com/2014/1/changes_to_xnu_mach_ipc.html).

First, the Rosetta 2 `runtime` calls `sys_fileport_makeport` to create a new Mach port (Figure 1).
The file descriptor of an x86_64 executable is passed as the first argument.

<figure>
    <img src="../assets/sys_fileport_makeport.png">
    <figcaption>Figure 1 Decompilation of the function in the <code>runtime</code> calling <code>sys_fileport_makeport</code> to make a new Mach port.</figcaption>
</figure>

Through the created Mach port, `oahd` receives the file descriptor of the x86_64 executable (Figure 2).
It then calculates the SHA-256 hash from the file path and the file contents (Figure 3) and uses that hash to search for an existing AOT file.
If not found, `oahd` executes `oahd-helper` to create a new AOT file.

<figure>
    <img src="../assets/fileport_makefd_at_oahd.png">
    <figcaption>Figure 2 Decompilation of the function in <code>oahd</code> calling <code>sys_fileport_makefd</code>.</figcaption>
</figure>

<figure>
    <img src="../assets/calc_sha256.png">
    <figcaption>Figure 3 Decompilation of the function in <code>oahd</code> calculating the SHA-256 hash.</figcaption>
</figure>

The file descriptor of the AOT file (created or found by the search) is sent back to the Rosetta 2 `runtime` via Mach IPC.
The Rosetta 2 `runtime` calls `sys_fileport_makefd` to receive the file descriptor of the AOT file (Figure 4).

<figure>
    <img src="../assets/fileport_makefd_at_runtime.png">
    <figcaption>Figure 4 Decompilation of the function in the <code>runtime</code> calling <code>sys_fileport_makefd</code>.</figcaption>
</figure>

The Rosetta 2 `runtime` parses the received AOT file (`FUN_00008424` in Figure 5) and maps it onto memory for each segment (`mmap_aot_file` in Figure 5).
In the `FUN_00008424` function, `FUN_00008814` (named `load_macho`) is called to load Mach-O files.
We will see the details of `load_macho` in the next section.

<figure>
    <img src="../assets/comm_parse_mmap_aot_files.png">
    <figcaption>Figure 5 Decompilation of the <code>runtime</code> parsing and memory-mapping AOT files.</figcaption>
</figure>

Figure 6 summarizes the overview of this execution flow.

<figure>
    <img src="../assets/system_overview.png">
    <figcaption>Figure 6 Schematic picture of how AOT files are mapped into memory through Mach IPC between <code>runtime</code> and <code>oahd</code>.</figcaption>
</figure>

Before going to the next, let's discuss the difference between Rosetta 2 and Windows 10 on Arm x86 emulation.

In Windows 10 on Arm, the module filehandle to be translated is passed from `xtajit.dll` to `XtaCache.exe` via ALPC (for more details, see [Cylance Research team blog post](https://blogs.blackberry.com/en/2019/09/teardown-windows-10-on-arm-x86-emulation)).
Although the way to pass x86 (or x86_64) executables is almost the same as Rosetta 2, translated files are created at different times in Windows 10 on Arm and Rosetta 2.

In Rosetta 2, AOT files are created by `oahd-helper` before the actual start of an x86\_64 executable.
The created AOT files are then used when running the x86_64 executable firstly.
Therefore, in the case of Rosetta 2, if the size of the x86_64 code to be translated is large, it will take some time to start the program for the first time.

On the other hand, in the case of Windows 10 on Arm, XTA cache files are created after (or while) an x86 executable runs.
The XTA cache files are not used at the application's first launch.
Therefore, although the startup itself is fast, the subsequent process tends to be slower because the x86 code is JIT-translated during the execution.

### Feature of Rosetta 2 `runtime`: parsing AOT files (a new command `LC_AOT_METADATA`)

As mentioned in part1, an AOT file itself is just a Mach-O file.
So, AOT files pass the runtime information, such as addresses to be mapped and the entry points, to the loader through load commands.

In the Rosetta 2 `runtime`, the `load_macho` function parses these load commands.
Notably, it parses a command called `LC_AOT_METADATA`, which is specific to AOT files (Figure 7).

<figure>
    <img src="../assets/lc_aot_metadata.png">
    <figcaption>Figure 7 Decompilation of the <code>load_macho</code> parsing <code>LC_AOT_METADATA</code>.</figcaption>
</figure>

`LC_AOT_METADATA` is a load command with the 0xcacaca01 command number.
The contents of the record cannot be displayed by `otool`.
It is currently an undocumented load command.

```
$ otool -l hello.out.aot
(...snip...)
Load command 4
      cmd ?(0xcacaca01) Unknown load command
  cmdsize 32
000000b8 00000021 000000e0 00000001 00003f60 00000000
(...snip...)
```

The following is the reverse-engineering result of `LC_AOT_METADATA` command structure.
It contains the information about the code section and the offset to the path name of the x86\_64 executable.

```c
struct lc_aot_metadata {
    uint32_t cmd;                  // 0xcacaca01
    uint32_t cmdsize;              // Always 32
    uint32_t offset_to_image_path; // Offset to image path name of x86_64 executable from AOT file's __LINKEDIT segment
    uint32_t image_path_length;    // Length of image path name
    uint32_t field_0x10;           // unknown
    uint32_t field_0x14;           // unknown (always 1, otherwise an x86_64 application will crash)
    uint32_t x86_64_code_section;  // RVA of x86_64 code section
    uint32_t field_0x1c;           // unknown
};
```

We can set the `x86_64_code_section` to an invalid value and still run the application without any problem.

As for `image_path_length` and `offset_to_image_path`, if an integer overflow does not occur, they can be set to invalid values.
These two records are probably used for debugging purposes.

## Rosetta 2 `runtime`'s debugging features

The Rosetta 2 `runtime` retains some features that were probably used internally by Apple for debugging purposes.
This can be enabled by passing strings starting with the prefix `ROSETTA_` as an environment variable\*.
If these strings are passed, the global variables that control debugging features will be set to 1.

> \* The value is obtained from a structure holding the environment variables on the stack. The initialization of this structure seems to be performed by the kernel.

Figure 8 shows the function in Rosetta 2 `runtime` enabling the debugging features.

<figure>
    <img src="../assets/debugging_features.png" />
    <figcaption>Figure 8 Decompilation of the function in Rosetta 2 <code>runtime</code> enabling the debugging features.</figcaption>
</figure>

I confirmed the following debugging features in the Rosetta 2 `runtime`.

- `ROSETTA_PRINT_IR`
- `ROSETTA_PRINT_SEGMENTS`
- `ROSETTA_ALLOW_GUARD_PAGES`
- `ROSETTA_DISABLE_EXCEPTIONS`
- `ROSETTA_AOT_ERRORS_ARE_FATAL`

In this article, I will discuss the `ROSETTA_PRINT_IR` and `ROSETTA_PRINT_SEGMENTS`.

### `ROSETTA_PRINT_IR`

`ROSETTA_PRINT_IR` is a debugging feature to show the x86\_64 code being translated to the standard error output.
If the flag is enabled, the `show_log` (defined at `runtime+0x57694`) function will be called in the `translate` function described in [part1](part1.md#jit-binary-translation-of-rosetta-2-runtime-translate-function) to display the x86\_64 code being translated (Figure 9).

<figure>
    <img src="../assets/print_ir_in_translate.png" />
    <figcaption>Figure 9 <code>translate</code> in <code>runtime</code> calling <code>show_log</code> to show the translated x86_64 code.</figcaption>
</figure>

Let me show you an example output by `show_log`.
Let's take the program executing the [shellcode in part1](part1.md#target-application), and check the output when the `ROSETTA_PRINT_IR` function is enabled.
Start LLDB, write 1 to the `ROSETTA_PRINT_IR` flag, and execute the program.

```
(lldb) process launch --stdout out.log --stderr print_ir.log
* thread #2, stop reason = exec
    frame #0: 0x00007ffdfff7a46c runtime`_mh_execute_header + 9324
runtime`_mh_execute_header:
->  0x7ffdfff7a46c <+9324>: mov    x19, sp
    0x7ffdfff7a470 <+9328>: and    sp, x19, #0xfffffffffffffff0
    0x7ffdfff7a474 <+9332>: mov    x29, sp
    0x7ffdfff7a478 <+9336>: ldr    x20, [x19, #0x20]
Target 0: (runtime) stopped.
(lldb) memory write 0x7ffdfffeda4e 1
(lldb) c
```

After the execution, I got [a standard error output](./assets/print_ir.log).
Here is the snippet of this log.

```
20002a939    BB_1
             preds     BB_0
20002a939    mov       eax, [r13 + 0x4]
20002a93d    add       r13, rax
20002a940    inc       ebx
20002a942    cmp       ebx, esi, def #nzcvpa
20002a944    jcc       ne, 0x20002a678, fallthrough BB_2

20002a94a    BB_2
             preds     BB_1
20002a94a    jmp       BB_3

20002a96d    BB_3
             flags liveout #nzcvpa, livein <none>
             preds     BB_2
20002a96d    cmp       [rbp - 0x40], 0x0, def #nzcvpa
20002a972    jcc       ne, BB_13, fallthrough BB_4

(...snip...) 
```

You can see that the leftmost column shows the address where the instruction exists, and the next column shows the corresponding x86_64 assembly.
In addition, for each basic block, metadata such as `preds` and `flags` are listed.

The `preds` points to the basic block from which the jump is made.

The details about flags `liveout #nzcvpa and livein <none>` is currently unknown, but it probably indicates the flag register changes when these instructions are executed.

Next, look at the disassembly result around 0x1082f4000.

```
(...snip...)

(JIT translated x86_64 code)
1082f4000    BB_0
             preds
1082f4000    xor       rax, rax
1082f4003    cdq
1082f4004    push      rax
1082f4005    mov       rdi, 0x68732f6e69622f2f
1082f400f    push      rdi
1082f4010    push      rsp
1082f4011    pop       rdi
1082f4012    xor       rsi, rsi
1082f4015    mov       al, 0x2
1082f4017    ror       rax, 0x28
1082f401b    mov       al, 0x3b
1082f401d    syscall   fallthrough BB_1
```

You can see that this is the JIT-executed x86_64 code in the [sample in part1](part1.md#target-application).
The `ROSETTA_PRINT_IR` debugging feature can likely be used to trace the translated x86\_64 code.

### `ROSETTA_PRINT_SEGMENTS`

`ROSETTA_PRINT_SEGMENTS` is a debugging feature that displays the map status of AOT files, Rosetta 2 `runtime`, and executable segments to the memory.
As in the previous section, after running the program via LLDB, we can get the following logs by enabling `ROSETTA_PRINT_SEGMENTS`.

- [A standard error when `ROSETTA_PRINT_SEGMENTS` is enabled](./assets/print_segments_err.log)
- [A standard output when `ROSETTA_PRINT_SEGMENTS` is enabled](./assets/print_segments_out.log)

Firstly, let's look at the standard error.

```
runtime mapped at 0x7ffdfff78000
segments for /var/db/oah/16c6785d8fdab5ee2435f23dc2962ceda2e76042ea2ad1517687c5bb7358bf00/b3690b640c30cc1cd5d018dfefc14f1069ab08653c96f0d1c1028c0088a7832e/run_shellcode.out.aot:
    mapping __TEXT at [0x100010000, 0x1000111e8)
    mapping RuntimeRoutines at [0x100012000, 0x100016000)
    mapping __LINKEDIT at [0x100017000, 0x100017168)
```

You can see that it shows the address that the Rosetta 2 `runtime` is mapped to, and where the segments of the AOT files are mapped to.

Comparing this with the `vmmap` command result, we can see that it does indeed match.

```
mapped file                 100010000-100012000    [    8K     8K     0K     0K] r-x/rwx SM=COW          /private/var/db/*/run_shellcode.out.aot
mapped file                 100012000-100016000    [   16K    16K     0K     0K] r-x/r-x SM=COW          /Library/Apple/*/runtime
mapped file                 100017000-100018000    [    4K     4K     0K     0K] r--/rwx SM=COW          /private/var/db/*/run_shellcode.out.aot
```

Next, let's take a look at the standard output.

```
Re-using existing aot shared cache:
  [0x0, 0x106e0000) init_prot=1 max_prot=1
  [0x106e0000, 0x11138000) init_prot=3 max_prot=3
  [0x11138000, 0x9ae54000) init_prot=85 max_prot=85
    [0x7ffe963e4000, 0x7ffe963e75ac] RuntimeRoutines
    [0x7ffe963e75ac, 0x7ffe963e8594] /usr/lib/system/libsystem_blocks.dylib
    [0x7ffe963e8594, 0x7ffe964382a4] /usr/lib/system/libxpc.dylib
    [0x7ffe964382a4, 0x7ffe9645b00c] /usr/lib/system/libsystem_trace.dylib
    [0x7ffe9645b00c, 0x7ffe965031bc] /usr/lib/system/libcorecrypto.dylib
    [0x7ffe965031bc, 0x7ffe9653da4c] /usr/lib/system/libsystem_malloc.dylib
    (...snip...)
(...snip...)
```

It likely shows a list of addresses where each dylib is mapped.
Again, let's compare it with the result of `vmmap`.

```
(...snip...)
mapped file              7ffe852ac000-7ffe9598c000 [262.9M  32.8M     0K     0K] r--/r-- SM=COW          Object_id=8f689f0f
mapped file              7ffe963e4000-7fff20100000 [  2.2G  59.4M     0K     0K] r-x/r-x SM=COW          Object_id=8f689f0f
__TEXT                   7fff20146000-7fff20148000 [    8K     8K     0K     0K] r-x/r-x SM=COW          /usr/lib/system/libsystem_blocks.dylib
__TEXT                   7fff20148000-7fff2017e000 [  216K   152K     0K     0K] r-x/r-x SM=COW          /usr/lib/system/libxpc.dylib
__TEXT                   7fff2017e000-7fff20196000 [   96K    80K     0K     0K] r-x/r-x SM=COW          /usr/lib/system/libsystem_trace.dylib
__TEXT                   7fff20196000-7fff20235000 [  636K   124K     0K     0K] r-x/r-x SM=COW          /usr/lib/system/libcorecrypto.dylib
__TEXT                   7fff20235000-7fff20262000 [  180K   132K     0K     0K] r-x/r-x SM=COW          /usr/lib/system/libsystem_malloc.dylib
(...snip...)
```

Oddly enough, there seems to be a discrepancy with the result of `ROSETTA_PRINT_SEGMENTS`.
According to the `vmmap` result, `libsystem_blocks.dylib` is mapped to [0x7fff20146000, 0x7fff20148000].
However, the results of `ROSETTA_PRINT_SEGMENTS` output says it is mapped to [0x7ffe963e75ac, 0x7ffe963e8594].

Also, when you look at the addresses mapped by `ROSETTA_PRINT_SEGMENTS` in the `vmmap` command result, you can figure out that a single huge file of 2.2GB is mapped.

```
(...snip...)
mapped file              7ffe963e4000-7fff20100000 [  2.2G  59.4M     0K     0K] r-x/r-x SM=COW          Object_id=8f689f0f
(...snip...)
```

What is this file?

This is an AOT shared cache file, which is displayed at the top of the log.
Next, let's take a deeper look at the contents of the AOT shared cache file.

## AOT shared cache file

### Quick look at AOT shared cache file

You may think of `dyld_shared_cache` when you hear "shared cache."

In fact, you can find a new file corresponding to the AOT shared cache in the folder where `dyld_shared_cache` is.

```
$ ls -lh /System/Library/dyld/
total 7733712
-rwxr-xr-x  1 root  admin   2.4G  1  1  2020 aot_shared_cache
-rwxr-xr-x  1 root  admin     0B  1  1  2020 aot_shared_cache.t8027
-rwxr-xr-x  1 root  admin   2.1G  1  1  2020 dyld_shared_cache_arm64e
-rwxr-xr-x  1 root  admin   729K  1  1  2020 dyld_shared_cache_arm64e.map
-rwxr-xr-x  1 root  admin   2.3G  1  1  2020 dyld_shared_cache_x86_64
-rwxr-xr-x  1 root  admin   562K  1  1  2020 dyld_shared_cache_x86_64.map
-rwxr-xr-x  1 root  admin   2.3G  1  1  2020 dyld_shared_cache_x86_64h
-rwxr-xr-x  1 root  admin   562K  1  1  2020 dyld_shared_cache_x86_64h.map
```

You can also see that the file size is about 2.4GB, which is roughly the same size as the file mentioned at the end of the previous section.
This file seems to be mapped into the memory.

Now, let's check the file type of `aot_shared_cache` with the `file` command.

```
$ file /System/Library/dyld/aot_shared_cache
/System/Library/dyld/aot_shared_cache: data
```

Oops, the `file` command says `data`.

Let's also look at the results from Patrick Wardle's excellent tool [WYS](https://objective-see.com/products/whatsyoursign.html).
In general, WYS is better than the `file` command at estimating file types.
Unfortunately, however, it also displays `data` as the file type (Figure 10).

<figure>
    <img src="../assets/WYS.png" />
    <figcaption>Figure 10 WYS says its file type is data.</figcaption>
</figure>

It seems to be a file type that is not yet publicly known.

I did some search on the web about AOT shared cache files.
However, it seems that the file format has not been analyzed yet.

### Analyzing AOT shared cache files

Since there was no analysis of the file format, I decided to analyze it on my own.

After digging Rosetta 2 `runtime`, I found that the function `0x13cbc+runtime` in the Rosetta 2 `runtime` is loading the AOT shared cache file.
I named this function `load_aot_shared_cache`.

As far as I know, `load_aot_shared_cache` does the following.

- It gets the base address of the region where the AOT shared cache file is mapped by using the [`shared_region_check_np` system call](https://github.com/apple/darwin-xnu/blob/8f02f2a044b9bb1ad951987ef5bab20ec9486310/bsd/vm/vm_unix.c#L1913-L1938).
    - Like the `dyld_shared_cache`, the purpose of loading the AOT shared cache file is to improve the performance of the process initialization.
- It checks the magic number and the version information in the AOT shared cache file.
- If `ROSETTA_PRINT_SEGMENTS` is enabled, it shows the segment information of the AOT shared cache file to standard output.
- It calls the function `0x13908+runtime` (named `parse_aot_shared_cache`) to parse the AOT shared cache file and store some fields as global variables.

The file structure of the AOT shared cache file is determined by reverse-engineering the `parse_aot_shared_cache`. 
The file structure is shown below (Figure 11).

<figure>
    <img src="../assets/aot_shared_cache_structure.png">
    <figcaption>Figure 11 Schematic picture of the AOT shared cache file structure.</figcaption>
</figure>

First, the header contains information such as the offset to the subsequent segments, the offset size to the code signature, and so on.
Each member of the header of the AOT shared cache looks like this.

```c
// It seems to be the same structure as _shared_region_mapping_np
// See https://opensource.apple.com/source/dyld/dyld-95.3/src/ImageLoaderMachO.cpp.auto.html
struct AotCacheMappingInfo {
    uint64_t address;
    uint64_t size;
    uint64_t file_offset;
    uint32_t init_prot;
    uint32_t max_prot;
};

struct AotCacheHeader {
    uint64_t magic;                        // Always 0x6568636143746F41 ("AotCache" in ASCII)
    uint64_t field_0x8;                    // Unknown
    uint64_t field_0x10;                   // Unknown
    uint64_t uuid[2];                      // UUID
    uint64_t version[4];                   // Version of AOT shared cache
    uint64_t offset_to_codesig;            // Offset to code signature of AOT shared cache
    uint64_t size_of_codesig;              // Size of code signature of AOT shared cache
    uint32_t n_entries;                    // Number of entries of meta data
    uint32_t offset_to_metadata_seg;       // Offset to metadata segment
    struct AotCacheMappingInfo mapping[3]; // Information of each segment
};
```

After the AOT shared cache header, there is a metadata segment.
It contains three sets of data: code fragment metadata, branch data, and instruction map, as many as the number of images in the AOT shared cache.

The code fragment metadata has the following structure.

```c
struct CodeFragmentMetadata {
    uint32_t type;                  // 1 (Rosetta 2 runtime) 0 (AOT file without file header)
    uint32_t offset_to_path_name;   // Offset to path name from the text segment
    uint32_t offset_to_x64_code;    // Offset to x64 code from the text segment
    uint32_t size_of_x64_code;      // Size of x64 code
    uint32_t offset_to_arm64_code;  // Offset to arm64 code from the aot segment
    uint32_t size_of_arm64_code;    // Size of arm64 code
    uint32_t offset_to_branch_data; // Offset to branch data from the meta data segment
    uint32_t size_of_branch_data;   // Size of branch data
    uint32_t offset_to_insn_map;    // Offset to instruction map from the meta data segment
    uint32_t size_of_insn_map;      // Size of instruction map from the meta data segment
};
```

The branch data and the instruction map structures are unknown.
We can guess that the structure holds the correspondence between the arm64 code and x86_64 code addresses in the AOT shared cache from these names.

The AOT segment follows the metadata segment, which contains the data from the Rosetta 2 `runtime` and the dylib AOT files for various systems.

After the AOT segment, you can see that there is a code signature.
This is used to verify the integrity of the AOT shared cache before it is loaded into the memory.

Next, let's look at how the AOT shared cache is mapped onto the memory (Figure 12).

<figure>
    <img src="../assets/aot_shared_cache_mapped.png">
    <figcaption>Figure 12 Schematic picture of memory-mapped AOT shared cache files.</figcaption>
</figure>

When it is mapped onto the memory, two new segments are added (green rectangles in Figure 12).
The text segment followed by the AOT segment contains the path information of the image in the AOT shared cache and the x86_64 code.
The two members of `CodeFragmentMetadata`, `offset_to_path_name`, and `offset_to_x64_code`, are the offsets from the starting address of this segment.

The text segment information is not contained in the AOT shared cache file, and it is not clear which file contains it. I suspect that this information is extracted from `dyld_shared_cache` and written to the memory.

### AotSharedCacheExtractor

Based on the reverse-engineering results, I created a [Python script](https://github.com/FFRI/ProjectChampollion/blob/main/AotSharedCacheExtractor/main.py) parsing AOT shared cache files and dumps the information in them.

Currently, two commands have been implemented to dump the header information of the AOT shared cache files and extract the code signature of them.

```
$ python main.py dump /path/to/aot_shared_cache
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
        size_of_arm64_code: 0x35ac
        offset_to_branch_data: 0x0
        size_of_branch_data: 0x0
        offset_to_insn_map: 0x0
        size_of_insn_map: 0x0
[0x106e0000, 0x106e35ac] RuntimeRoutines
CodeFragmentMetaData:
        type: 0x0
        offset_to_path_name: 0x46880
        offset_to_x64_code: 0x47279
        size_of_x64_code: 0x5df
        offset_to_arm64_code: 0x35ac
        size_of_arm64_code: 0xfe8
        offset_to_branch_data: 0x50
        size_of_branch_data: 0x7c
        offset_to_insn_map: 0xcc
        size_of_insn_map: 0x190
[0x106e35ac, 0x106e4594] /usr/lib/system/libsystem_blocks.dylib
        branch data: [0x4050, 0x40cc]
        instruction map: [0x40cc, 0x425c]
...

$ python extract-codesig /path/to/aot_shared_cache codesig
Will extract a code signature located at [0x9a3fc000, 0x9b74400b]
The extracted code signature is saved to code_sig
$ file code_sig
code_sig: Mac OS X Detached Code Signature (non-executable) - 20217867 bytes
```

This can be used to find out which address in AOT shared cache files contain what image, or to dump the header information.

Note that I have only tested this with `aot_shared_cache` in macOS Bug Sur version 11.1.
Please be aware of this when using this script on your environment.

## Conclusion

In part2, I have explained the following three features of the Rosetta 2 `runtime`.

- Inter-process communication with `oahd`, through which file descriptors for x86_64 executables and AOT files are passed.
- Parsing `LC_AOT_MEATADATA` command specific to Mach-O in AOT files
- Logging in debug mode
    - Showing translated x86\_64 code by `ROSETTA_PRINT_IR`
    - Showing the address of the mapped AOT files and the address range of each image in the AOT shared cache file by `ROSETTA_PRINT_SEGMENTS`.

I also introduced the AOT shared cache file and its file structure.

Recently, Arm processors have been adopted for laptop and server applications, not limited to embedded applications.
In this processor transition, two different emulation technologies have been introduced by Microsoft and Apple.
In the past, Apple has introduced Rosetta, but this is the first time that several different OS vendors have introduced similar emulation technology at the same time.

As briefly discussed in this article (["Feature of Rosetta 2 `runtime`: communicating with `oahd`"](#feature-of-rosetta-2-runtime-communicating-with-oahd)), there are some differences between the two technologies.
Examining the differences between the two technologies can provide useful insights for future developers of similar emulation technologies.

I hope that this article will lead to further analysis of Rosetta 2 and research on how it differs from the Windows 10 on Arm x86 emulation.

