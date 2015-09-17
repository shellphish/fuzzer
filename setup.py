import os
import shutil
import subprocess
from distutils.errors import LibError
from distutils.core import setup
from distutils.command.build import build as _build

AFL_INSTALL_PATH = os.path.join("bin", "afl")
SUPPORTED_ARCHES = ["aarch64", "x86_64", "i386", "arm", "ppc", "ppc64", "mips", "mips64"]

# grab the afl-other-arch repo
if not os.path.exists(AFL_INSTALL_PATH):
    AFL_REPO = "git@git.seclab.cs.ucsb.edu:shellphish/afl-other-arch.git"
    if subprocess.call(['git', 'clone', AFL_REPO, AFL_INSTALL_PATH]) != 0:
        raise LibError("Unable to retrieve afl-other-arch")

# TODO GRAB CGC AFL STUFF

def _build_afl():
    if subprocess.call(['./build.sh'] + SUPPORTED_ARCHES, cwd=AFL_INSTALL_PATH) != 0:
        raise LibError("Unable to build afl-other-arch")

class build(_build):
    def run(self):
            self.execute(_build_afl, (), msg="Building AFL")
            _build.run(self)
cmdclass = {'build': build}


setup(
    name='fuzzer', version='0.1', description="Python wrapper for multiarch AFL",
    packages=['fuzzer'],
    data_files=[
        ('bin', ('bin/afl',),),
    ],
    cmdclass=cmdclass,
)
