## @file dump_parser.py
# @brief Parsing engine for dumped process files

from typing import Dict, List

_DUMP_MAGIC = b'CHRONOSDUMP'
_DUMP_REGS = ['RAX', 'RBX', 'RCX', 'RDX', 'RDI', 'RSI', 'RBP', 'RSP', 'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15', 'CS', 'DS', 'SS']

class _WrongDumpMagicException(Exception):
    """!
    @brief Exception class raised if magic value of Chronos Dump is wrong
    """

    def __init__(self) -> None:
        """!
        @brief Constructor for WrongDumpMagicException class
        """

        super().__init__("Wrong magic for dump file")

class ProcMapping:
    """!
    @brief Class used to store a process page
    """

    start_addr: int = 0
    end_addr: int = 0
    data: bytearray = b''
    name: str = '[anon]'

    def __init__(self, start_addr: int, end_addr: int, data: bytearray, name: str) -> None:
        """!
        @brief Constructor for ProcMapping class

        @param start_addr: Page start address
        @param end_addr: Page end address
        @param data: Page content
        @param name: Page name
        """

        self.start_addr = start_addr
        self.end_addr = end_addr
        self.data = data
        self.name = name

class FileDescriptor:
    """!
    @brief Class used to store a file descriptor
    """

    file_path: str = ''
    fd: int = 0
    flags: int = 0
    cursor: int = 0

    def __init__(self, file_path: str, fd: int, flags: int, cursor: int) -> None:
        """!
        @brief Constructor for FileDescriptor class

        @param file_path: Path to file
        @param fd: File descriptor of file (number)
        @param flags: Flags the process was opened with
        @param cursor: Cursor position in file
        """

        self.file_path = file_path
        self.fd = fd
        self.flags = flags
        self.cursor = cursor

class DumpResult:
    """!
    @brief Class used to store dump parsed parameters
    """

    sym_addr : int = 0
    regs : Dict[str, int] = {}
    fs_base : int = 0
    gs_base : int = 0
    params : List[int] = []
    curr_brk : int = 0
    fds : List[FileDescriptor] = []
    mappings : List[int] = []

class DumpParser:
    """!
    @brief Engine for extracting parameters from Chronos dump files
    """

    _dump_data = None

    def __init__(self, dump_path: str) -> None:
        """!
        @brief Constructor for DumpParser class

        @param dump_path: Path to Chronos dump file
        """

        with open(dump_path, 'rb') as dump_f:
            self._dump_data = dump_f.read()
        if not self._check_magick():
            raise _WrongDumpMagicException()

    def _check_magick(self) -> None:
        """!
        @brief Checks magic value from Chronos dump file
        """

        return self._dump_data[:len(_DUMP_MAGIC)] == _DUMP_MAGIC

    def process(self) -> None:
        """!
        @brief Processes Chronos dump file to extract its parameters
        """

        res = DumpResult()
        curr_pos = len(_DUMP_MAGIC)

        # HOOKED FUNCTION ADDRESS
        res.sym_addr = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
        curr_pos += 8

        # STATE REGISTERS
        for reg_i in range(len(_DUMP_REGS)):
            res.regs[_DUMP_REGS[reg_i]] = int.from_bytes(self._dump_data[curr_pos+reg_i*8:curr_pos+reg_i*8+8], 'little')
        curr_pos += len(_DUMP_REGS) * 8

        # FS BASE ADDRESS
        res.fs_base = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
        curr_pos += 8

        # GS BASE ADDRESS
        res.gs_base = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
        curr_pos += 8

        # HOOKED FUNCTION PARAMETERS
        params_cnt = int.from_bytes(self._dump_data[curr_pos:curr_pos+1], 'little')
        curr_pos += 1
        for param_i in range(params_cnt):
            param_val = int.from_bytes(self._dump_data[curr_pos+param_i*8:curr_pos+param_i*8+8], 'little')
            res.params.append(param_val)
        curr_pos += params_cnt * 8

        # PROCESS CURRENT BRK ADDRESS
        res.curr_brk = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
        curr_pos += 8

        # PROCESS OPEN FILE DESCRIPTORS
        while self._dump_data[curr_pos] != 0:
            file_path = self._dump_data[curr_pos:curr_pos+256]
            file_path = file_path[:file_path.find(b'\x00')].decode()
            curr_pos += len(file_path) + 1
            fd = int.from_bytes(self._dump_data[curr_pos:curr_pos+4], 'little')
            curr_pos += 4
            flags = int.from_bytes(self._dump_data[curr_pos:curr_pos+4], 'little')
            curr_pos += 4
            cursor = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
            curr_pos += 8
            file_descriptor = FileDescriptor(file_path, fd, flags, cursor)
            res.fds.append(file_descriptor)
        curr_pos += 1

        # PROCESS MAPPINGS
        while curr_pos < len(self._dump_data):
            mapping_name = self._dump_data[curr_pos:curr_pos+256]
            mapping_name = mapping_name[:mapping_name.find(b'\x00')].decode()
            curr_pos += 256
            mapping_start_addr = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
            curr_pos += 8
            mapping_end_addr = int.from_bytes(self._dump_data[curr_pos:curr_pos+8], 'little')
            curr_pos += 8
            mapping_sz = mapping_end_addr - mapping_start_addr
            mapping_data = self._dump_data[curr_pos:curr_pos+mapping_sz]
            mapping = ProcMapping(mapping_start_addr, mapping_end_addr, mapping_data, mapping_name)
            curr_pos += mapping_sz
            res.mappings.append(mapping)

        return res