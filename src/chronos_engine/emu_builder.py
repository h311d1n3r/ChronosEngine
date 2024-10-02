## @file emu_builder.py
# @brief Build engine for Qiling emulation of Chronos dump

from qiling import Qiling
from qiling.os.filestruct import PersistentQlFile
from copy import deepcopy
from typing import Dict, List
import os

from .dump_parser import DumpResult, ProcMapping, FileDescriptor
from .abi_manager import AbiManager

_MSR_ADDRESSES = {
    'FS': 0xC0000100,
    'GS': 0xC0000101
}

class _WrongSegmentRegException(Exception):
    """!
    @brief Exception class raised when an unknown segment register is being accessed
    """

    def __init__(self, reg_name: str) -> None:
        """!
        @brief Constructor for WrongSegmentRegException class

        @param reg_name: Unknown segment register name
        """

        super().__init__("Wrong segment register :", reg_name)

class EmuBuilder:
    """!
    @brief Build engine class for Qiling emulation of Chronos dump
    """

    _ql = None

    def __init__(self, ql: Qiling) -> None:
        """!
        @brief Constructor for EmuBuilder class

        @param ql: The Qiling instance
        """

        self._ql = ql
        self._abi_manager = AbiManager(ql)

    def _unmap_all(self) -> None:
        """!
        @brief Unmaps all pages of given Qiling emulation instance, except kernel special ones
        """

        kernel_segs = ['[vvar]', '[vsyscall]']
        for m_info in deepcopy(self._ql.mem.map_info):
            start_addr, end_addr, _, name = m_info[0:4]
            if name in kernel_segs:
                continue
            self._ql.mem.unmap(start_addr, end_addr - start_addr)

    def _set_sym_addr(self, sym_addr: int) -> None:
        """!
        @brief Set target function address for emulation

        @param sym_addr: Target function address
        """

        self._abi_manager.write_pc(sym_addr)

    def _set_regs(self, regs: Dict[str, int]) -> None:
        """!
        @brief Set context registers for emulation

        @param regs: Map of context registers [reg_name, reg_value]
        """

        for reg_name in regs:
            reg_val = regs[reg_name]
            self._ql.arch.regs.write(reg_name, reg_val)

    def _set_segment_base(self, segment_reg: str, segment_base: int) -> None:
        """!
        @brief Edit MSR registers to associate segment registers with their segment base address

        @param segment_reg: Name of segment register
        @param segment_base: Base address of segment
        """

        segment_reg = segment_reg.upper()
        if segment_reg not in _MSR_ADDRESSES:
            raise _WrongSegmentRegException(segment_reg)
        msr_addr = _MSR_ADDRESSES[segment_reg]
        self._ql.arch.msr.write(msr_addr, segment_base)

    def _set_params(self, params: List[int]) -> None:
        """!
        @brief Set function parameters based on ABI

        @param params: Values of parameters
        """

        self._abi_manager.write_call_params(params)

    def _set_brk(self, curr_brk: int) -> None:
        """!
        @brief Set current brk address for emulation

        @param curr_brk: Current brk address
        """

        self._ql.loader.brk_address = curr_brk

    def _map_pages(self, mappings: List[ProcMapping]) -> None:
        """!
        @brief Map process pages for emulation

        @param mappings: Process pages
        """

        for mapping in mappings:
            mapping_sz = mapping.end_addr - mapping.start_addr
            self._ql.mem.map(mapping.start_addr, mapping_sz, info=mapping.name)
            self._ql.mem.write(mapping.start_addr, mapping.data)

    def _add_vvar_mapping(self) -> None:
        """!
        @brief Add [vvar] segment into memory between [stack] and [vdso]
        """

        stack_end = 0
        vdso_start = 0
        for mapping in self._ql.mem.map_info:
            mapping_start, mapping_end, _, mapping_name = mapping[:4]
            if mapping_name == '[stack]':
                stack_end = mapping_end
            elif mapping_name == '[vdso]' and vdso_start == 0:
                vdso_start = mapping_start
        self._ql.mem.map(stack_end, vdso_start - stack_end, info='[vvar]')

    def _open_files(self, fds: List[FileDescriptor]) -> None:
        """!
        @brief Open files previously opened by dumped process and map them to correct file descriptors

        @param fds: Files opened by process
        """
        for fd in fds:
            if not os.path.exists(fd.file_path):
                continue
            ql_file = PersistentQlFile.open(fd.file_path, fd.flags, 0o644)
            ql_file.seek(fd.cursor)
            self._ql.os.fd[fd.fd] = ql_file

    def build(self, dump: DumpResult) -> None:
        """!
        @brief Prepare emulation by integrating all dump parameters into Qiling instance

        @param dump: Dump parameters
        """

        self._unmap_all()
        self._set_sym_addr(dump.sym_addr)
        self._set_regs(dump.regs)
        self._set_segment_base('FS', dump.fs_base)
        self._set_segment_base('GS', dump.gs_base)
        self._set_params(dump.params)
        self._set_brk(dump.curr_brk)
        self._map_pages(dump.mappings)
        self._add_vvar_mapping()
        self._open_files(dump.fds)