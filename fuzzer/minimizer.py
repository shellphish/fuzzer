import os
import angr
import shutil
import tempfile
import subprocess
from .fuzzer import Fuzzer

import logging
l = logging.getLogger("fuzzer.Minimizer")

class Minimizer(object):
    """Testcase minimizer"""

    def __init__(self, binary_path, testcase):
        """
        :param binary_path: path to the binary which the testcase applies to
        :param testcase: string representing the contents of the testcase
        """

        self.binary_path = binary_path
        self.testcase = testcase

        Fuzzer._perform_env_checks()

        self.base = Fuzzer._get_base()
        l.debug("got base dir %s", self.base)

        # unfortunately here is some code reuse between Fuzzer and Minimizer
        p = angr.Project(self.binary_path)
        tracer_dir = p.arch.qemu_name
        afl_dir = "afl-%s" % p.loader.main_bin.os

        self.tmin_path = os.path.join(self.base, "bin", afl_dir, "afl-tmin")

        self.afl_path_var = os.path.join(self.base, "bin", afl_dir, "tracers", tracer_dir)

        l.debug("tmin_path: %s", self.tmin_path)
        l.debug("afl_path_var: %s", self.afl_path_var)

        os.environ['AFL_PATH'] = self.afl_path_var

        # create temp
        self.work_dir = tempfile.mkdtemp(prefix='tmin-', dir='/tmp/')

        # flag for work directory removal
        self._removed = False

        self.input_testcase = os.path.join(self.work_dir, 'testcase')
        self.output_testcase = os.path.join(self.work_dir, 'minimized_result')

        l.debug("input_testcase: %s", self.input_testcase)
        l.debug("output_testcase: %s", self.output_testcase)

        # populate contents of input testcase
        with open(self.input_testcase, 'w') as f:
            f.write(testcase)

    def __del__(self):
        if not self._removed:
            shutil.rmtree(self.work_dir)

    def minimize(self):
        """Start minimizing"""

        self._start_minimizer().wait()

        result = open(self.output_testcase).read()

        shutil.rmtree(self.work_dir)
        self._removed = True

        return result

    def _start_minimizer(self, memory="8G"):

        args = [self.tmin_path]

        args += ["-i", self.input_testcase]
        args += ["-o", self.output_testcase]
        args += ["-m", memory]
        args += ["-Q"]

        args += ["--"]
        args += [self.binary_path]

        outfile = "minimizer.log"

        l.debug("execing: %s > %s", " ".join(args), outfile)

        outfile = os.path.join(self.work_dir, outfile)
        fp = open(outfile, "w")

        return subprocess.Popen(args, stderr=fp)
