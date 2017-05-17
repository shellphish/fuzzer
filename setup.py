import os
from distutils.core import setup

setup(
    name='fuzzer', version='1.1', description="Python wrapper for multiarch AFL",
    packages=['fuzzer', 'fuzzer.extensions'],
    data_files = [ ("bin", (os.path.join("bin", "create_dict.py"),)) ],
    scripts = [ 'shellphuzz' ],
    install_requires=['angr', 'shellphish-qemu', 'shellphish-afl', 'tqdm']
)
