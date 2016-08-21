# Fuzzer

This module provides a Python wrapper for interacting with AFL (American Fuzzy Lop: http://lcamtuf.coredump.cx/afl/).
It supports starting an AFL instance, adding slave workers, injecting and retrieving testcases, and checking various performance metrics.
Shellphish used it in Mechanical Phish (our CRS for the Cyber Grand Challenge) to interact with AFL.

## Installation

/!\ We recommend installing our Python packages in a Python virtual environment. That is how we do it, and you'll likely run into problems if you do it otherwise.

The fuzzer has some dependencies.
First, here's a probably-incomplete list of debian packages that might be useful:

    sudo apt-get install build-essential libtool automake autoconf bison debootstrap debian-archive-keyring
    sudo apt-get build-dep qemu

Then, the fuzzer also depends on `shellphish-afl`, which is a pip package that actually includes AFL:

    pip install git+https://github.com/shellphish/shellphish-afl
    
That'll pull a ton of other stuff, compile qemu about 4 times, and set everything up.
Then, install this fuzzer wrapper:

    pip install git+https://github.com/shellphish/fuzzer

## Usage

Big TODO.
For now, `import fuzzer` and figure it out ;-)
