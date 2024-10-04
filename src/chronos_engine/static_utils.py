## @file static_utils.py
# @brief Utilities related to static operations

import subprocess
import os
import hashlib

def compile_stub() -> str:
    """!
    @brief Compiles a stub ELF binary to be passed as an argument for Qiling emulation

    @return Path to the stub binary
    """

    work_dir = '/tmp/chronos-' + hashlib.md5(os.urandom(16)).hexdigest() + '/'
    os.makedirs(work_dir)
    
    stub_src_path = work_dir+'stub.c'
    stub_build_path = work_dir+'stub'
    
    with open(stub_src_path, 'wb') as stub_src_f:
        stub_src_f.write(b'int main() {}')

    compile_stub_cmd = f'gcc {stub_src_path} -o {stub_build_path}'.split(' ')
    subprocess.run(compile_stub_cmd, check=True)
    
    return stub_build_path