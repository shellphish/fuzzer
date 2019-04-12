import os
import angr
import shutil
import tempfile
import subprocess
import shellphish_afl

import logging
l = logging.getLogger("phuzzer.Minimizer")

class Minimizer:
    """Testcase minimizer"""

    def __init__(self, binary_path, testcase):
        """
        :param binary_path: path to the binary which the testcase applies to
        :param testcase: string representing the contents of the testcase
        """

        self.binary_path = binary_path
        self.testcase = testcase

        AFL.check_environment()

        # unfortunately here is some code reuse between Phuzzer and Minimizer
        p = angr.Project(self.binary_path)
        tracer_id = 'cgc' if p.loader.main_object.os == 'cgc' else p.arch.qemu_name
        self.tmin_path = os.path.join(shellphish_afl.afl_dir(tracer_id), "afl-tmin")
        self.afl_path_var = shellphish_afl.afl_path_var(tracer_id)

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
        with open(self.input_testcase, 'wb') as f:
            f.write(testcase)

    def __del__(self):
        if not self._removed:
            shutil.rmtree(self.work_dir)

    def minimize(self):
        """Start minimizing"""

        self._start_minimizer().wait()

        with open(self.output_testcase, 'rb') as f: result = f.read()

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
        with open(outfile, "wb") as fp:
            return subprocess.Popen(args, stderr=fp)

from .phuzzers import AFL
