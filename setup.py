import os
import shutil
import subprocess
from distutils.errors import LibError
from distutils.core import setup
from distutils.command.build import build as _build

AFL_UNIX_INSTALL_PATH = os.path.join("bin", "afl-unix")
AFL_CGC_INSTALL_PATH = os.path.join("bin", "afl-cgc")
SUPPORTED_ARCHES = ["aarch64", "x86_64", "i386", "arm", "ppc", "ppc64", "mips", "mips64"]

# grab the afl-other-arch repo
if not os.path.exists(AFL_UNIX_INSTALL_PATH):
    AFL_UNIX_REPO = "git@git.seclab.cs.ucsb.edu:shellphish/afl-other-arch.git"
    if subprocess.call(['git', 'clone', AFL_UNIX_REPO, AFL_UNIX_INSTALL_PATH]) != 0:
        raise LibError("Unable to retrieve afl-unix")

if not os.path.exists(AFL_CGC_INSTALL_PATH):
    AFL_CGC_REPO = "git@git.seclab.cs.ucsb.edu:cgc/driller-afl.git"
    if subprocess.call(['git', 'clone', AFL_CGC_REPO, AFL_CGC_INSTALL_PATH]) != 0:
        raise LibError("Unable to retrieve afl-cgc")

def _build_all():

    # build afls
    if subprocess.call(['./build.sh'] + SUPPORTED_ARCHES, cwd=AFL_UNIX_INSTALL_PATH) != 0:
        raise LibError("Unable to build afl-other-arch")

    if subprocess.call(['make'], cwd=AFL_CGC_INSTALL_PATH) != 0:
        raise LibError("Unable to make afl-cgc")

    if subprocess.call(['./build_qemu_support.sh'], cwd=os.path.join(AFL_CGC_INSTALL_PATH, "qemu_mode")) != 0:
        raise LibError("Unable to build afl-cgc-qemu")

    # grab libraries
    if subprocess.call(["./fetchlibs.sh"], cwd=".") != 0:
        raise LibError("Unable to fetch libraries")

class build(_build):
    def run(self):
            self.execute(_build_all, (), msg="Building AFL and grabbing libraries")
            _build.run(self)
cmdclass = {'build': build}

AFL_UNIX_FUZZ = os.path.join(AFL_UNIX_INSTALL_PATH)
AFL_CGC_FUZZ  = os.path.join(AFL_CGC_INSTALL_PATH)

# get data_files ready for exporting, probably a better way to do this
data_files = [
    (AFL_UNIX_FUZZ, (os.path.join(AFL_UNIX_FUZZ, "afl-fuzz"),),),
    (AFL_CGC_FUZZ, (os.path.join(AFL_CGC_FUZZ, "afl-fuzz"),),),
    ]

for ARCH in SUPPORTED_ARCHES:
    TRACER_STR = os.path.join(AFL_UNIX_INSTALL_PATH, "tracers", ARCH)
    data_files.append((TRACER_STR, (os.path.join(TRACER_STR, "afl-qemu-trace"),),))

# add cgc
TRACER_STR = os.path.join(AFL_CGC_INSTALL_PATH, "tracers", "i386")
data_files.append((TRACER_STR, (os.path.join(TRACER_STR, "afl-qemu-trace"),),))

setup(
    name='fuzzer', version='0.1', description="Python wrapper for multiarch AFL",
    packages=['fuzzer'],
    data_files=data_files,
    cmdclass=cmdclass,
)
