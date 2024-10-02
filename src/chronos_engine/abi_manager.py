## @file abi_manager.py
# @brief Application Binary Interface manager for Linux x86-64 platform

from qiling import Qiling
from typing import List

_PC_REG = 'RIP'
_CALL_REGS = ['RDI', 'RSI', 'RDX', 'RCX', 'R8', 'R9']
_STACK_REG = 'RSP'
_PLATFORM_SZ = 64
_PTR_SZ = _PLATFORM_SZ // 8

class AbiManager:
    """!
    @brief Application Binary Interface class manager for Linux x86-64 platform
    """

    _ql: Qiling = None

    def __init__(self, ql: Qiling) -> None:
        """!
        @brief Constructor for AbiManager class

        @param ql: The Qiling instance
        """

        self._ql = ql

    def write_call_params(self, params: List[int]) -> None:
        """!
        @brief Use platform calling convention to write function parameters

        @param params: Values of function parameters
        """

        for param_i, param in enumerate(params):
            if param_i < len(_CALL_REGS):
                self._ql.arch.regs.write(_CALL_REGS[param_i], param)
            else:
                param_bytes = int.to_bytes(param, _PTR_SZ, 'little')
                self._ql.mem.write(_STACK_REG + (param_i - len(_CALL_REGS)) * _PTR_SZ, param_bytes)

    def write_pc(self, new_pc: int) -> None:
        """!
        @brief Write value of platform Program Counter register

        @param new_pc: Value of Program Counter
        """

        self._ql.arch.regs.write(_PC_REG, new_pc)