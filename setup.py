import os
from distutils.core import setup

setup(
    name='phuzzer', version='1.1', description="Python wrapper for multiarch AFL",
    packages=['phuzzer', 'phuzzer.extensions'],
    data_files = [ ("bin", (os.path.join("bin", "create_dict.py"),)) ],
    scripts = [ 'shellphuzz' ],
    install_requires=['angr', 'shellphish-qemu', 'shellphish-afl', 'tqdm']
)
