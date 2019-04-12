import os
import angr
import shutil
import tempfile
import subprocess
import shellphish_afl

import logging
l = logging.getLogger("phuzzer.Showmap")

class Showmap:
    """Show map"""

    def __init__(self, binary_path, testcase, timeout=None):
        """
        :param binary_path: path to the binary which the testcase applies to
        :param testcase: string representing the contents of the testcase
        :param timeout: millisecond timeout
        """

        self.binary_path = binary_path
        self.testcase = testcase
        self.timeout = None

        if isinstance(binary_path, str):
            self.is_multicb = False
            self.binaries = [binary_path]
        elif isinstance(binary_path, (list,tuple)):
            self.is_multicb = True
            self.binaries = binary_path
        else:
            raise ValueError("Was expecting either a string or a list/tuple for binary_path! "
                "It's {} instead.".format(type(binary_path)))

        if timeout is not None:
            if isinstance(timeout, int):
                self.timeout = str(timeout)
            elif isinstance(timeout, (str)):
                self.timeout = timeout
            elif isinstance(timeout, (bytes)):
                self.timeout = timeout.decode('utf-8')
            else:
                raise ValueError("timeout param must be of type int or str")

        # will be set by showmap's return code
        self.causes_crash = False

        AFL.check_environment()

        # unfortunately here is some code reuse between Phuzzer and Minimizer (and Showmap!)
        p = angr.Project(self.binaries[0])
        tracer_id = 'cgc' if p.loader.main_object.os == 'cgc' else p.arch.qemu_name
        if self.is_multicb:
            tracer_id = 'multi-{}'.format(tracer_id)

        self.showmap_path = os.path.join(shellphish_afl.afl_dir(tracer_id), "afl-showmap")
        self.afl_path_var = shellphish_afl.afl_path_var(tracer_id)

        l.debug("showmap_path: %s", self.showmap_path)
        l.debug("afl_path_var: %s", self.afl_path_var)

        os.environ['AFL_PATH'] = self.afl_path_var

        # create temp
        self.work_dir = tempfile.mkdtemp(prefix='showmap-', dir='/tmp/')

        # flag for work directory removal
        self._removed = False

        self.input_testcase = os.path.join(self.work_dir, 'testcase')
        self.output = os.path.join(self.work_dir, 'out')

        l.debug("input_testcase: %s", self.input_testcase)
        l.debug("output: %s", self.output)

        # populate contents of input testcase
        with open(self.input_testcase, 'wb') as f:
            f.write(testcase)

    def __del__(self):
        if not self._removed:
            shutil.rmtree(self.work_dir)

    def showmap(self):
        """Create the map"""

        if self._start_showmap().wait() == 2:
            self.causes_crash = True

        with open(self.output) as f: result = f.read()

        shutil.rmtree(self.work_dir)
        self._removed = True

        shownmap = dict()
        for line in result.split("\n")[:-1]:
            key, h_count = map(int, line.split(":"))
            shownmap[key] = h_count

        return shownmap

    def _start_showmap(self, memory="8G"):

        args = [self.showmap_path]

        args += ["-o", self.output]
        if not self.is_multicb:
            args += ["-m", memory]
        args += ["-Q"]

        if self.timeout:
            args += ["-t", self.timeout]
        else:
            args += ["-t", "%d+" % (len(self.binaries) * 1000)]

        args += ["--"]
        args += self.binaries

        outfile = "minimizer.log"

        l.debug("execing: %s > %s", " ".join(args), outfile)

        outfile = os.path.join(self.work_dir, outfile)
        with open(outfile, "w") as fp, open(self.input_testcase, 'rb') as it, open("/dev/null", 'wb') as devnull:
            return subprocess.Popen(args, stdin=it, stdout=devnull, stderr=fp, close_fds=True)

from .phuzzers import AFL
