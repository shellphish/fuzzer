import os
from distutils.core import setup

setup(
    name='fuzzer', version='1.0', description="Python wrapper for multiarch AFL",
    packages=['fuzzer', 'fuzzer.extensions'],
    data_files = [ ("bin", (os.path.join("bin", "create_dict.py"),)) ],
    install_requires=['angr', 'shellphish-qemu', 'shellphish-afl']
)
