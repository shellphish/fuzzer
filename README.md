# Fuzzer

This module provides a Python wrapper for interacting with AFL (American Fuzzy Lop: http://lcamtuf.coredump.cx/afl/).
It supports starting an AFL instance, adding slave workers, injecting and retrieving testcases, and checking various performance metrics.
Shellphish used it in Mechanical Phish (our CRS for the Cyber Grand Challenge) to interact with AFL.

## Installation

/!\ We recommend installing our Python packages in a Python virtual environment. That is how we do it, and you'll likely run into problems if you do it otherwise.

The fuzzer has some dependencies.
First, here's a probably-incomplete list of debian packages that might be useful:

    sudo apt-get install build-essential gcc-multilib libtool automake autoconf bison debootstrap debian-archive-keyring libtool-bin
    sudo apt-get build-dep qemu

Then, the fuzzer also depends on `shellphish-afl`, which is a pip package that actually includes AFL:

    pip install git+https://github.com/shellphish/shellphish-afl
    
That'll pull a ton of other stuff, compile qemu about 4 times, and set everything up.
Then, install this fuzzer wrapper:

    pip install git+https://github.com/shellphish/fuzzer

## Usage

There are two ways of using this package.
The easy way is to use the `shellphuzz` script, which allows you to specify various options, enable [driller](https://www.internetsociety.org/sites/default/files/blogs-media/driller-augmenting-fuzzing-through-selective-symbolic-execution.pdf), etc.
The script has explanations about its usage with `--help`.

A quick example:

```
# fuzz with 4 AFL cores
shellphuzz -i -c 4 /path/to/binary

# perform symbolic-assisted fuzzing with 4 AFL cores and 2 symbolic tracing (drilling) cores.
shellphuzz -i -c 4 -d 2 /path/to/binary
```

You can also use it programmatically, but we have no documentation for that.
For now, `import fuzzer` or look at the shellphuz script and figure it out ;-)
