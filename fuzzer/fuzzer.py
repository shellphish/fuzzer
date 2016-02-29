import os
import time
import angr
import tempfile
import subprocess

import logging

l = logging.getLogger("fuzzer.fuzzer")

config = { }

class InstallError(Exception):
    pass

class EarlyCrash(Exception):
    pass

class Fuzzer(object):
    ''' Fuzzer object, spins up a fuzzing job on a binary '''

    def __init__(self, binary_path, work_dir, afl_count=1, library_path=None, time_limit=None,
            target_opts=None, extra_opts=None, create_dictionary=False,
            seeds=None):
        '''
        :param binary_path: path to the binary to fuzz
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param library_path: library path to use, if none is specified a default is chosen
        :param timelimit: amount of time to fuzz for, has no effect besides returning True when calling timed_out
        :param seeds: list of inputs to seed fuzzing with
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up
        '''

        self.binary_path    = binary_path
        self.work_dir       = work_dir
        self.afl_count      = afl_count
        self.time_limit     = time_limit
        self.library_path   = library_path
        self.target_opts    = [ ] if target_opts is None else target_opts
        self.seeds          = ["fuzz"] if seeds is None or len(seeds) == 0 else seeds

        # check for afl sensitive settings
        with open("/proc/sys/kernel/core_pattern") as f:
            if not "core" in f.read():
                l.error("AFL Error: Pipe at the beginning of core_pattern")
                raise InstallError("execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'")

        with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
            if not "performance" in f.read():
                l.error("AFL Error: Suboptimal CPU scaling governor")
                raise InstallError("execute 'cd /sys/devices/system/cpu; echo performance | sudo tee cpu*/cpufreq/scaling_governor'")

        # binary id
        self.binary_id = os.path.basename(binary_path)

        self.job_dir  = os.path.join(self.work_dir, self.binary_id)
        self.in_dir   = os.path.join(self.job_dir, "input")
        self.out_dir  = os.path.join(self.job_dir, "sync")

        # sanity check extra opts
        self.extra_opts = extra_opts
        if self.extra_opts is not None:
            if not isinstance(self.extra_opts, list):
                raise ValueError("extra_opts must be a list of command line arguments")

        # base of the fuzzer package
        self.base = os.path.dirname(__file__)
        self._adjust_base()

        self.start_time       = int(time.time())
        # create_dict script
        self.create_dict_path = os.path.join(self.base, "bin", "create_dict.py")
        # afl dictionary
        self.dictionary       = None
        # processes spun up
        self.procs            = [ ]
        # start the fuzzer ids at 0
        self.fuzz_id          = 0
        # test if we're resuming an old run
        self.resuming         = bool(os.listdir(self.out_dir)) if os.path.isdir(self.out_dir) else False
        # has the fuzzer been turned on?
        self._on = False

        # the AFL build path for afl-qemu-trace-*
        p = angr.Project(binary_path)
        tracer_dir            = p.arch.qemu_name
        afl_dir               = "afl-%s" % p.loader.main_bin.os

        # the path to AFL capable of calling driller
        self.afl_path         = os.path.join(self.base, "bin", afl_dir, "afl-fuzz")

        self.afl_path_var     = os.path.join(self.base, "bin", afl_dir, "tracers", tracer_dir)
        self.qemu_dir         = self.afl_path_var

        l.debug("self.start_time: %r", self.start_time)
        l.debug("self.afl_path: %s", self.afl_path)
        l.debug("self.afl_path_var: %s", self.afl_path_var)
        l.debug("self.qemu_dir: %s", self.qemu_dir)
        l.debug("self.binary_id: %s", self.binary_id)
        l.debug("self.work_dir: %s", self.work_dir)
        l.debug("self.resuming: %s", self.resuming)

        # if we're resuming an old run set the input_directory to a '-'
        if self.resuming:
            l.info("[%s] resuming old fuzzing run", self.binary_id)
            self.in_dir = "-"

        else:
            # create the work directory and input directory
            try:
                os.makedirs(self.in_dir)
            except OSError:
                l.warning("unable to create in_dir \"%s\"", self.in_dir)

            # populate the input directory
            self._initialize_seeds()

        # look for a dictionary
        dictionary_file = os.path.join(self.job_dir, "%s.dict" % self.binary_id)
        if os.path.isfile(dictionary_file):
            self.dictionary = dictionary_file

        # if a dictionary doesn't exist and we aren't resuming a run, create a dict
        elif not self.resuming:
            # call out to another process to create the dictionary so we can
            # limit it's memory
            if create_dictionary:
                if self._create_dict(dictionary_file):
                    self.dictionary = dictionary_file
                else:
                    # no luck creating a dictionary
                    l.warning("[%s] unable to create dictionary", self.binary_id)

        # set environment variable for the AFL_PATH
        os.environ['AFL_PATH'] = self.afl_path_var

        # set up libraries
        self._export_library_path(p)

    ### EXPOSED
    def start(self):
        '''
        start fuzzing
        '''

        # test to see if the binary is so bad it crashes on our test case
        if self._crash_test():
            raise EarlyCrash

        # spin up the AFL workers
        self._start_afl()

        self._on = True

    @property
    def alive(self):
        if not self._on:
            return False

        alive_cnt = 0
        if self._on:
            for fuzzer in self.stats:
                try:
                    os.kill(int(self.stats[fuzzer]['fuzzer_pid']), 0)
                    alive_cnt += 1
                except OSError:
                    pass

        return bool(alive_cnt)

    def kill(self):
        for p in self.procs:
            p.terminate()
            p.wait()

        self._on = False

    @property
    def stats(self):

        # collect stats into dictionary
        stats = {}
        if os.path.isdir(self.out_dir):
            for fuzzer_dir in os.listdir(self.out_dir):
                stat_path = os.path.join(self.out_dir, fuzzer_dir, "fuzzer_stats")
                if os.path.isfile(stat_path):
                    stats[fuzzer_dir] = {}

                    with open(stat_path, "rb") as f:
                        stat_blob = f.read()
                        stat_lines = stat_blob.split("\n")[:-1]
                        for stat in stat_lines:
                            key, val = stat.split(":")
                            stats[fuzzer_dir][key.strip()] = val.strip()

        return stats

    def found_crash(self):

        for job in self.stats:
            try:
                if int(self.stats[job]['unique_crashes']) > 0:
                    return True
            except KeyError:
                pass

        return False

    def add_fuzzer(self):
        '''
        add one fuzzer
        '''

        self.procs.append(self._start_afl_instance())

    def add_fuzzers(self, n):
        for _ in range(n):
            self.add_fuzzer()

    def remove_fuzzer(self):
        '''
        remove one fuzzer
        '''

        try:
            f = self.procs.pop()
        except IndexError:
            l.error("no fuzzer to remove")
            raise ValueError("no fuzzer to remove")

        f.kill()

    def remove_fuzzers(self, n):
        '''
        remove multiple fuzzers
        '''

        if n > len(self.procs):
            l.error("not more than %u fuzzers to remove", n)
            raise ValueError("not more than %u fuzzers to remove" % n)

        if n == len(self.procs):
            l.warning("removing all fuzzers")

        for _ in range(n):
            self.remove_fuzzer()

    def crashes(self):
        '''
        retrieve the crashes discovered by AFL
        :return: a list of strings which are crashing inputs
        '''

        crashes = set()
        for fuzzer in os.listdir(self.out_dir):
            crashes_dir = os.path.join(self.out_dir, fuzzer, "crashes")

            if not os.path.isdir(crashes_dir):
                # if this entry doesn't have a crashes directory, just skip it
                continue

            for crash in os.listdir(crashes_dir):
                if crash == "README.txt":
                    # skip the readme entry
                    continue

                crash_path = os.path.join(crashes_dir, crash)
                with open(crash_path, 'rb') as f:
                    crashes.add(f.read())

        return list(crashes)

    def queue(self, fuzzer='fuzzer-master'):
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''

        if not fuzzer in os.listdir(self.out_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        queue_path = os.path.join(self.out_dir, fuzzer, 'queue')
        queue_files = filter(lambda x: x != ".state", os.listdir(queue_path))

        return map(lambda f: open(os.path.join(queue_path, f)).read(), queue_files)

    def bitmap(self, fuzzer='fuzzer-master'):
        '''
        retrieve the bitmap for the fuzzer `fuzzer`.
        :return: a string containing the contents of the bitmap.
        '''

        if not fuzzer in os.listdir(self.out_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        bitmap_path = os.path.join(self.out_dir, fuzzer, "fuzz_bitmap")

        return open(bitmap_path).read()

    def timed_out(self):
        if self.time_limit is None:
            return False
        return time.time() - self.start_time > self.time_limit

    def pollenate(self, testcases):
        '''
        pollenate a fuzzing job with new testcases

        :param testcases: list of strings representing new inputs to introduce
        '''

        nectary_queue_directory = os.path.join(self.out_dir, 'pollen', 'queue')
        if not 'nectary' in os.listdir(self.out_dir):
            os.makedirs(nectary_queue_directory)

        pollen_cnt = len(os.listdir(nectary_queue_directory))

        for tcase in testcases:
            with open(os.path.join(nectary_queue_directory, "id:%06d,src:pollenation" % pollen_cnt), "w") as f:
                f.write(tcase)

            pollen_cnt += 1

    ### FUZZ PREP

    def _initialize_seeds(self):
        '''
        populate the input directory with the seeds specified
        '''

        assert len(self.seeds) > 0, "Must specify at least one seed to start fuzzing with"

        l.debug("initializing seeds %r", self.seeds)

        template = os.path.join(self.in_dir, "seed-%d")
        for i, seed in enumerate(self.seeds):
            with open(template % i, "wb") as f:
                f.write(seed)

    ### DICTIONARY CREATION

    def _create_dict(self, dict_file):

        l.debug("creating a dictionary of string references within binary \"%s\"",
                self.binary_id)

        args = [self.create_dict_path, self.binary_path, dict_file]

        p = subprocess.Popen(args)
        retcode = p.wait()

        return True if retcode == 0 else False

    ### BEHAVIOR TESTING

    def _crash_test(self):

        args = [os.path.join(self.qemu_dir, "afl-qemu-trace"), self.binary_path]

        fd, jfile = tempfile.mkstemp()
        os.close(fd)

        with open(jfile, 'w') as f:
            f.write("fuzz")

        with open(jfile, 'r') as i:
            with open('/dev/null', 'w') as o:
                p = subprocess.Popen(args, stdin=i, stdout=o)
                p.wait()

                if p.poll() < 0:
                    ret = True
                else:
                    ret = False

        os.remove(jfile)
        return ret

    ### AFL SPAWNERS

    def _start_afl_instance(self, memory="8G"):

        args = [self.afl_path]

        args += ["-i", self.in_dir]
        args += ["-o", self.out_dir]
        args += ["-m", memory]
        args += ["-Q"]
        if self.fuzz_id == 0:
            args += ["-M", "fuzzer-master"]
            outfile = "fuzzer-master.log"
        else:
            args += ["-S", "fuzzer-%d" % self.fuzz_id]
            outfile = "fuzzer-%d.log" % self.fuzz_id

        if self.dictionary is not None:
            args += ["-x", self.dictionary]

        if self.extra_opts is not None:
            args += self.extra_opts

        args += ["--", self.binary_path]

        args.extend(self.target_opts)

        l.debug("execing: %s > %s", ' '.join(args), outfile)

        outfile = os.path.join(self.job_dir, outfile)
        fp = open(outfile, "w")

        # increment the fuzzer ID
        self.fuzz_id += 1

        return subprocess.Popen(args, stdout=fp)

    def _start_afl(self):
        '''
        start up a number of AFL instances to begin fuzzing
        '''

        # spin up the master AFL instance
        master = self._start_afl_instance() # the master fuzzer
        self.procs.append(master)

        if self.afl_count > 1:
            driller = self._start_afl_instance()
            self.procs.append(driller)

        # only spins up an AFL instances if afl_count > 1
        for _ in range(2, self.afl_count):
            slave = self._start_afl_instance()
            self.procs.append(slave)

    ### UTIL

    def _adjust_base(self):
        '''
        adjust self.base to point to the directory containing bin, there should always be a directory
        containing bin below base intially
        '''

        while not "bin" in os.listdir(self.base) and os.path.abspath(self.base) != "/":
            self.base = os.path.join(self.base, "..")

        if os.path.abspath(self.base) == "/":
            raise InstallError("could not find afl install directory")

    def _export_library_path(self, p):
        '''
        export the correct library path for a given architecture
        '''
        path = None

        if self.library_path is None:
            directory = None
            if p.arch.qemu_name == "aarch64":
                directory = "arm64"
            if p.arch.qemu_name == "i386":
                directory = "i386"
            if p.arch.qemu_name == "mips":
                directory = "mips"
            if p.arch.qemu_name == "mipsel":
                directory = "mipsel"
            if p.arch.qemu_name == "ppc":
                directory = "powerpc"
            if p.arch.qemu_name == "arm":
                # some stuff qira uses to determine the which libs to use for arm
                progdata = open(self.binary_path, "rb").read(0x800)
                if "/lib/ld-linux.so.3" in progdata:
                    directory = "armel"
                elif "/lib/ld-linux-armhf.so.3" in progdata:
                    directory = "armhf"

            if directory is None:
                l.warning("architecture \"%s\" has no installed libraries", p.arch.qemu_name)
            else:
                path = os.path.join(self.base, "bin", "fuzzer-libs", directory)
        else:
            path = self.library_path

        if path is not None:
            l.debug("exporting QEMU_LD_PREFIX of '%s'", path)
            os.environ['QEMU_LD_PREFIX'] = path
