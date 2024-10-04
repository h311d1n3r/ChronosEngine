## @file chronos.py
# @brief Chronos engine for emulation. It coordinates the logic specific to each task

from qiling import Qiling
from qiling.const import QL_ARCH, QL_OS, QL_VERBOSE
from qiling.arch.models import X86_CPU_MODEL
import os

from .dump_parser import DumpParser
from .emu_builder import EmuBuilder
from .static_utils import compile_stub

class ChronosEngine:
    """!
    @brief Chronos engine class for emulation. It coordinates the logic specific to each task
    """

    _dump_path = None

    def __init__(self, dump_path: str) -> None:
        """!
        @brief Constructor for ChronosEngine class

        @param dump_path: Path to the Chronos dump file
        """

        self._dump_path = dump_path

    def process(self) -> Qiling:
        """!
        @brief Processes the Chronos dump file to build a Qiling instance

        @return A Qiling instance
        """

        if not os.path.exists(self._dump_path):
            raise FileNotFoundError(f"No such file or directory: '{self._dump_path}'")

        d_parser = DumpParser(self._dump_path)
        dump = d_parser.process()

        stub_path = compile_stub()
        ql = Qiling([stub_path], rootfs='/', archtype=QL_ARCH.X8664, ostype=QL_OS.LINUX, verbose=QL_VERBOSE.DISABLED, cputype=X86_CPU_MODEL.AMD_EPYC_ROME)

        emu_builder = EmuBuilder(ql)
        emu_builder.build(dump)

        return ql