#
# (c) FFRI Security, Inc., 2021 / Author: FFRI Security, Inc.
#
import mmap
import os
from ctypes import Structure, c_uint32, c_uint64, sizeof
from typing import Iterable, List, Optional, cast

import typer

app = typer.Typer()


def show_err(msg: str) -> None:
    typer.secho(msg, err=True, fg=typer.colors.RED)


def show_warn(msg: str) -> None:
    typer.secho(msg, err=True, fg=typer.colors.YELLOW)


def show_log(msg: str) -> None:
    typer.secho(msg, err=True, fg=typer.colors.GREEN)


class AotCacheMappingInfo(Structure):
    """
    struct AotCacheMappingInfo {
        uint64_t address;
        uint64_t size;
        uint64_t file_offset;
        uint32_t init_prot;
        uint32_t max_prot;
    };
    """

    _fields_ = (
        ("address", c_uint64),
        ("size", c_uint64),
        ("file_offset", c_uint64),
        ("init_prot", c_uint32),
        ("max_prot", c_uint32),
    )

    def __str__(self) -> str:
        return f"""\tAotCacheMappingInfo:
\t\taddress: {hex(self.address)}
\t\tsize: {hex(self.size)}
\t\tfile_offset: {hex(self.file_offset)}
\t\tinit_prot: {hex(self.init_prot)}
\t\tmax_prot: {hex(self.max_prot)}
"""


class AotCacheHeader(Structure):
    """
    struct AotCacheHeader {
        uint64_t magic;
        uint64_t field_0x8;
        uint64_t field_0x10;
        uint64_t uuid[2];
        uint64_t version[4];
        uint64_t offset_to_codesig;
        uint64_t size_of_codesig;
        uint32_t n_entries;
        uint32_t offset_to_metadata_seg;
        struct AotCacheMappingInfo mapping[3];
    };
    """

    _fields_ = (
        ("magic", c_uint64),
        ("field_0x8", c_uint64),
        ("field_0x10", c_uint64),
        ("uuid", c_uint64 * 2),
        ("version", c_uint64 * 4),
        ("offset_to_codesig", c_uint64),
        ("size_of_codesig", c_uint64),
        ("n_entries", c_uint32),
        ("offset_to_metadata_seg", c_uint32),
        ("mapping", AotCacheMappingInfo * 3),
    )

    def __str__(self) -> str:
        return f"""AotCacheHeader:
\tmagic: {hex(self.magic)}
\tfield_0x8: {hex(self.field_0x8)}
\tfield_0x10: {hex(self.field_0x10)}
\tuuid: {[hex(self.uuid[i]) for i in range(2)]}
\tversion: {[hex(self.version[i]) for i in range(4)]}
\toffset_to_codesig: {hex(self.offset_to_codesig)}
\tsize_of_codesig: {hex(self.size_of_codesig)}
\tn_entries: {hex(self.n_entries)}
\toffset_to_metadata_seg: {hex(self.offset_to_metadata_seg)}
\tmapping:\n {''.join(str(self.mapping[i]) for i in range(3))}"""


class CodeFragmentMetaData(Structure):
    _fields_ = (
        ("type", c_uint32),
        ("offset_to_path_name", c_uint32),
        ("offset_to_x64_code", c_uint32),
        ("size_of_x64_code", c_uint32),
        ("offset_to_arm64_code", c_uint32),
        ("size_of_arm64_code", c_uint32),
        ("offset_to_branch_data", c_uint32),
        ("size_of_branch_data", c_uint32),
        ("offset_to_insn_map", c_uint32),
        ("size_of_insn_map", c_uint32),
    )

    def __str__(self) -> str:
        return f"""CodeFragmentMetaData:
\ttype: {hex(self.type)}
\toffset_to_path_name: {hex(self.offset_to_path_name)}
\toffset_to_x64_code: {hex(self.offset_to_x64_code)}
\tsize_of_x64_code: {hex(self.size_of_x64_code)}
\toffset_to_arm64_code: {hex(self.offset_to_arm64_code)}
\tsize_of_arm64_code: {hex(self.size_of_arm64_code)}
\toffset_to_branch_data: {hex(self.offset_to_branch_data)}
\tsize_of_branch_data: {hex(self.size_of_branch_data)}
\toffset_to_insn_map: {hex(self.offset_to_insn_map)}
\tsize_of_insn_map: {hex(self.size_of_insn_map)}"""


def load_aot_mapped_module_names(mapped_module_file: str) -> Optional[Iterable[str]]:
    if not os.path.exists(mapped_module_file):
        show_err(f"{mapped_module_file} does not exist")
        return None
    with open(mapped_module_file, "r") as fin:
        for line in fin.readlines():
            yield line.strip()


@app.command()
def show_modules(aot_cache_path: str) -> None:
    if not os.path.exists(aot_cache_path):
        show_err(f"{aot_cache_path} does not exist")
        return

    if (
        mapped_module_names := load_aot_mapped_module_names("aot_mapped_module_names")
    ) is None:
        return

    with open(aot_cache_path, "r+b") as fin:
        mm = mmap.mmap(fin.fileno(), 0)
        header = AotCacheHeader.from_buffer_copy(
            cast(bytes, mm[0 : sizeof(AotCacheHeader)]), 0
        )
        if header.magic != 0x6568636143746F41:
            show_err(f"magic should be AotCache")
            return

        typer.echo(header)

        code_seg_beg = header.mapping[1].address
        metadata_seg_beg = header.offset_to_metadata_seg
        typer.echo(f"metadata segment starts from {hex(metadata_seg_beg)}")
        cur_seek = header.offset_to_metadata_seg
        typer.echo(f"number of entries is {header.n_entries}")

        for _ in range(header.n_entries):
            entry = CodeFragmentMetaData.from_buffer_copy(
                cast(bytes, mm[cur_seek : cur_seek + sizeof(CodeFragmentMetaData)])
            )
            typer.echo(entry)
            cur_seek += sizeof(CodeFragmentMetaData)
            if entry.type == 0:
                if cur_seek != metadata_seg_beg + entry.offset_to_branch_data:
                    show_err("branch data does not follow")
                    show_err(
                        f"{hex(cur_seek)} {hex(metadata_seg_beg)} {hex(entry.offset_to_branch_data)}"
                    )
                    return
                branch_data_beg, branch_data_end = cur_seek, cur_seek + entry.size_of_branch_data
                cur_seek += entry.size_of_branch_data

                if cur_seek != metadata_seg_beg + entry.offset_to_insn_map:
                    show_err("instruction map data does not follow")
                    show_err(
                        f"{hex(cur_seek)} {hex(metadata_seg_beg)} {hex(entry.offset_to_insn_map)}"
                    )
                    return
                insn_map_beg, insn_map_end = cur_seek, cur_seek + entry.size_of_insn_map
                cur_seek += entry.size_of_insn_map

                cache_code_beg = code_seg_beg + entry.offset_to_arm64_code
                cache_code_end = cache_code_beg + entry.size_of_arm64_code

                typer.echo(
                    f"[{hex(cache_code_beg)}, {hex(cache_code_end)}] {next(mapped_module_names)}"
                )
                typer.echo(
                    f"\tbranch data: [{hex(branch_data_beg)}, {hex(branch_data_end)}]"
                )
                typer.echo(
                    f"\tinstruction map: [{hex(insn_map_beg)}, {hex(insn_map_end)}]"
                )
            elif entry.type == 1:
                runtime_begin = code_seg_beg + entry.offset_to_arm64_code
                runtime_end = runtime_begin + entry.size_of_arm64_code
                typer.echo(
                    f"[{hex(runtime_begin)}, {hex(runtime_end)}] RuntimeRoutines"
                )
            else:
                show_err(f"Unknown CodeSegmentMetadata entry ({hex(entry.type)})")
                return


if __name__ == "__main__":
    app()
