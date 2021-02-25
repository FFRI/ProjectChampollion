# Project Champollion

## About this project

Rosetta 2 is an emulation mechanism to run the x86\_64 applications on Arm-based Apple Silicon with Ahead-Of-Time (AOT) and Just-In-Time (JIT) binary translation.

The technical details of Rosetta 2 are partially documented, but not rich enough.
Project Champollion is a project aimed at revealing the internals of Rosetta 2.
Currently, it provides:

- reverse-engineering results of Rosetta 2 (published in the GitHub pages of this repository. You can check it from [here]())
- [analysis configurations for Ghidra](./ghidra) for analyzing AOT Mach-O binaries
- [parser of `aot_shared_cache`](./AotSharedCacheExtractor)

**Attention**

This project is a work in progress and might still contain some mistakes.
If you find any mistakes, please report them in the issue.

## Citing Project Champollion

To cite this repository, please add the following BibTeX entry.

```
@software{prj_champ_rosetta2,
  author = {Koh M. Nakagawa},
  title = {{Project Champollion: Reverse engineering Rosetta 2}}
  url = {https://github.com/FFRI/ProjectChampollion},
  version = {0.1.0},
  year = {2021},
}
```

## License

The tools of this project are distributed under [Apache License version 2.0](LICENSE).

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2021
