import os
import sys
import time
import angr
import signal
import shutil
import threading
import subprocess
import shellphish_afl

import logging

l = logging.getLogger("fuzzer.fuzzer")

config = { }

class InstallError(Exception):
    pass


#  http://stackoverflow.com/a/41450617
class InfiniteTimer():
    """A Timer class that does not stop, unless you want it to."""

    def __init__(self, seconds, target):
        self._should_continue = False
        self.is_running = False
        self.seconds = seconds
        self.target = target
        self.thread = None

    def _handle_target(self):
        self.is_running = True
        self.target()
        self.is_running = False
        self._start_timer()

    def _start_timer(self):
        if self._should_continue: # Code could have been running when cancel was called.
            self.thread = threading.Timer(self.seconds, self._handle_target)
            self.thread.start()

    def start(self):
        if not self._should_continue and not self.is_running:
            self._should_continue = True
            self._start_timer()
        else:
            print "Timer already started or running, please wait if you're restarting."

    def cancel(self):
        if self.thread is not None:
            self._should_continue = False # Just in case thread is running and cancel fails.
            self.thread.cancel()
        else:
            pass
            #print "Timer never started or failed to initialize."



class Fuzzer(object):
    ''' Fuzzer object, spins up a fuzzing job on a binary '''

    def __init__(
        self, binary_path, work_dir, afl_count=1, library_path=None, time_limit=None, memory="8G",
        target_opts=None, extra_opts=None, create_dictionary=False,
        seeds=None, crash_mode=False, never_resume=False, qemu=True, stuck_callback=None,
        force_interval=None, job_dir=None
    ):
        '''
        :param binary_path: path to the binary to fuzz. List or tuple for multi-CB.
        :param work_dir: the work directory which contains fuzzing jobs, our job directory will go here
        :param afl_count: number of AFL jobs total to spin up for the binary
        :param library_path: library path to use, if none is specified a default is chosen
        :param timelimit: amount of time to fuzz for, has no effect besides returning True when calling timed_out
        :param seeds: list of inputs to seed fuzzing with
        :param target_opts: extra options to pass to the target
        :param extra_opts: extra options to pass to AFL when starting up
        :param crash_mode: if set to True AFL is set to crash explorer mode, and seed will be expected to be a crashing input
        :param never_resume: never resume an old fuzzing run, even if it's possible
        :param qemu: Utilize QEMU for instrumentation of binary.
        :param memory: AFL child process memory limit (default: "8G")
        :param stuck_callback: the callback to call when afl has no pending fav's
        :param job_dir: a job directory to override the work_dir/binary_name path
        '''

        self.binary_path    = binary_path
        self.work_dir       = work_dir
        self.afl_count      = afl_count
        self.time_limit     = time_limit
        self.library_path   = library_path
        self.target_opts    = [ ] if target_opts is None else target_opts
        self.crash_mode     = crash_mode
        self.memory         = memory
        self.qemu           = qemu
        self.force_interval = force_interval

        Fuzzer._perform_env_checks()

        if isinstance(binary_path,basestring):
            self.is_multicb = False
            self.binary_id = os.path.basename(binary_path)
        elif isinstance(binary_path,(list,tuple)):
            self.is_multicb = True
            self.binary_id = os.path.basename(binary_path[0])
        else:
            raise ValueError("Was expecting either a string or a list/tuple for binary_path! It's {} instead.".format(type(binary_path)))

        # sanity check crash mode
        if self.crash_mode:
            if seeds is None:
                raise ValueError("Seeds must be specified if using the fuzzer in crash mode")
            l.info("AFL will be started in crash mode")

        self.seeds          = ["fuzz"] if seeds is None or len(seeds) == 0 else seeds

        self.job_dir  = os.path.join(self.work_dir, self.binary_id) if not job_dir else job_dir
        self.in_dir   = os.path.join(self.job_dir, "input")
        self.out_dir  = os.path.join(self.job_dir, "sync")

        # sanity check extra opts
        self.extra_opts = extra_opts
        if self.extra_opts is not None:
            if not isinstance(self.extra_opts, list):
                raise ValueError("extra_opts must be a list of command line arguments")

        # base of the fuzzer package
        self.base = Fuzzer._get_base()

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

        if never_resume and self.resuming:
            l.info("could resume, but starting over upon request")
            shutil.rmtree(self.job_dir)
            self.resuming = False

        if self.is_multicb:
            # Where cgc/setup's Dockerfile checks it out
            # NOTE: 'afl/fakeforksrv' serves as 'qemu', as far as AFL is concerned
            #       Will actually invoke 'fakeforksrv/multicb-qemu'
            #       This QEMU cannot run standalone (always speaks the forkserver "protocol"),
            #       but 'fakeforksrv/run_via_fakeforksrv' allows it.
            # XXX: There is no driller/angr support, and probably will never be.
            self.afl_path = shellphish_afl.afl_bin('multi-cgc')
            self.afl_path_var = shellphish_afl.afl_path_var('multi-cgc')
            self.qemu_name = 'TODO'
        else:

            p = angr.Project(binary_path)

            self.os = p.loader.main_bin.os

            self.afl_dir          = shellphish_afl.afl_dir(self.os)

            # the path to AFL capable of calling driller
            self.afl_path         = shellphish_afl.afl_bin(self.os)

            if self.os == 'cgc':
                self.afl_path_var = shellphish_afl.afl_path_var('cgc')
            else:
                self.afl_path_var = shellphish_afl.afl_path_var(p.arch.qemu_name)
                # set up libraries
                self._export_library_path(p)

            # the name of the qemu port used to run these binaries
            self.qemu_name = p.arch.qemu_name

        self.qemu_dir = self.afl_path_var

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
                    l.warning("done making dictionary")
                else:
                    # no luck creating a dictionary
                    l.warning("[%s] unable to create dictionary", self.binary_id)

        if self.force_interval is None:
            l.warning("not forced")
            self._timer = InfiniteTimer(30, self._timer_callback)
        else:
            l.warning("forced")
            self._timer = InfiniteTimer(self.force_interval, self._timer_callback)

        self._stuck_callback = stuck_callback

        # set environment variable for the AFL_PATH
        os.environ['AFL_PATH'] = self.afl_path_var

    ### EXPOSED
    def start(self):
        '''
        start fuzzing
        '''

        # spin up the AFL workers
        self._start_afl()

        # start the callback timer
        self._timer.start()

        self._on = True

    @property
    def alive(self):
        if not self._on or not len(self.stats):
            return False

        alive_cnt = 0
        if self._on:
            for fuzzer in self.stats:
                try:
                    os.kill(int(self.stats[fuzzer]['fuzzer_pid']), 0)
                    alive_cnt += 1
                except (OSError, KeyError):
                    pass

        return bool(alive_cnt)

    def kill(self):
        for p in self.procs:
            p.terminate()
            p.wait()

        if hasattr(self, "_timer"):
            self._timer.cancel()

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

        return len(self.crashes()) > 0

    def add_fuzzer(self):
        '''
        add one fuzzer
        '''

        self.procs.append(self._start_afl_instance())

    def add_extension(self, name):
        """
        Spawn the mutation extension `name`
        :param name: name of extension
        :returns: True if able to spawn extension
        """

        extension_path = os.path.join(os.path.dirname(__file__), "..", "fuzzer", "extensions", "%s.py" % name)
        rpath = os.path.realpath(extension_path)

        l.debug("Attempting to spin up extension %s", rpath)

        if os.path.exists(extension_path):
            args = [sys.executable, extension_path, self.binary_path, self.out_dir]

            outfile_leaf = "%s-%d.log" % (name, len(self.procs))
            outfile = os.path.join(self.job_dir, outfile_leaf)
            with open(outfile, "wb") as fp:
                p = subprocess.Popen(args, stderr=fp)
            self.procs.append(p)
            return True

        return False

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

    def _get_crashing_inputs(self, signals):
        """
        Retrieve the crashes discovered by AFL. Only return those crashes which
        recieved a signal within 'signals' as the kill signal.

        :param signals: list of valid kill signal numbers
        :return: a list of strings which are crashing inputs
        """

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

                attrs = dict(map(lambda x: (x[0], x[-1]), map(lambda y: y.split(":"), crash.split(","))))

                if int(attrs['sig']) not in signals:
                    continue

                crash_path = os.path.join(crashes_dir, crash)
                with open(crash_path, 'rb') as f:
                    crashes.add(f.read())

        return list(crashes)

    def crashes(self, signals=(signal.SIGSEGV, signal.SIGILL)):
        """
        Retrieve the crashes discovered by AFL. Since we are now detecting flag
        page leaks (via SIGUSR1) we will not return these leaks as crashes.
        Instead, these 'crashes' can be found with the leaks function.

        :param signals: list of valid kill signal numbers to override the default (SIGSEGV and SIGILL)
        :return: a list of strings which are crashing inputs
        """

        return self._get_crashing_inputs(signals)

    def queue(self, fuzzer='fuzzer-master'):
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''

        if not fuzzer in os.listdir(self.out_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        queue_path = os.path.join(self.out_dir, fuzzer, 'queue')
        queue_files = filter(lambda x: x != ".state", os.listdir(queue_path))

        queue_l = [ ]
        for q in queue_files:
            with open(os.path.join(queue_path, q), 'rb') as f:
                queue_l.append(f.read())

        return queue_l

    def bitmap(self, fuzzer='fuzzer-master'):
        '''
        retrieve the bitmap for the fuzzer `fuzzer`.
        :return: a string containing the contents of the bitmap.
        '''

        if not fuzzer in os.listdir(self.out_dir):
            raise ValueError("fuzzer '%s' does not exist" % fuzzer)

        bitmap_path = os.path.join(self.out_dir, fuzzer, "fuzz_bitmap")

        bdata = None
        try:
            with open(bitmap_path, "rb") as f:
                bdata = f.read()
        except IOError:
            pass

        return bdata

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
        if not 'pollen' in os.listdir(self.out_dir):
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

        l.warning("creating a dictionary of string references within binary \"%s\"",
                self.binary_id)

        args = [sys.executable, self.create_dict_path]
        args += self.binary_path if self.is_multicb else [self.binary_path]

        with open(dict_file, "wb") as dfp:
            p = subprocess.Popen(args, stdout=dfp)
            retcode = p.wait()

        return retcode == 0 and os.path.getsize(dict_file)

    ### AFL SPAWNERS

    def _start_afl_instance(self):

        args = [self.afl_path]

        args += ["-i", self.in_dir]
        args += ["-o", self.out_dir]
        args += ["-m", self.memory]

        if self.qemu:
            args += ["-Q"]

        if self.crash_mode:
            args += ["-C"]

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

        # auto-calculate timeout based on the number of binaries
        if self.is_multicb:
            args += ["-t", "%d+" % (1000 * len(self.binary_path))]

        args += ["--"]
        args += self.binary_path if self.is_multicb else [self.binary_path]

        args.extend(self.target_opts)

        l.debug("execing: %s > %s", ' '.join(args), outfile)

        # increment the fuzzer ID
        self.fuzz_id += 1

        outfile = os.path.join(self.job_dir, outfile)
        with open(outfile, "w") as fp:
            return subprocess.Popen(args, stdout=fp, close_fds=True)

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

    @staticmethod
    def _perform_env_checks():
        err = ""

        # check for afl sensitive settings
        with open("/proc/sys/kernel/core_pattern") as f:
            if not "core" in f.read():
                err += "AFL Error: Pipe at the beginning of core_pattern\n"
                err += "execute 'echo core | sudo tee /proc/sys/kernel/core_pattern'\n"

        # This file is based on a driver not all systems use
        # http://unix.stackexchange.com/questions/153693/cant-use-userspace-cpufreq-governor-and-set-cpu-frequency
        # TODO: Perform similar performance check for other default drivers.
        if os.path.exists("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"):
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor") as f:
                if not "performance" in f.read():
                    err += "AFL Error: Suboptimal CPU scaling governor\n"
                    err += "execute 'cd /sys/devices/system/cpu; echo performance | sudo tee cpu*/cpufreq/scaling_governor'\n"

        # TODO: test, to be sure it doesn't mess things up
        with open("/proc/sys/kernel/sched_child_runs_first") as f:
            if not "1" in f.read():
                err += "AFL Warning: We probably want the fork() children to run first\n"
                err += "execute 'echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first'\n"

        # Spit out all errors at the same time
        if err != "":
            l.error(err)
            raise InstallError(err)


    @staticmethod
    def _get_base():
        '''
        find the directory containing bin, there should always be a directory
        containing bin below base intially
        '''
        base = os.path.dirname(__file__)

        while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
            base = os.path.join(base, "..")

        if os.path.abspath(base) == "/":
            raise InstallError("could not find afl install directory")

        return base

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
            if p.arch.qemu_name == "x86_64":
                directory = "x86_64"
            if p.arch.qemu_name == "mips":
                directory = "mips"
            if p.arch.qemu_name == "mipsel":
                directory = "mipsel"
            if p.arch.qemu_name == "ppc":
                directory = "powerpc"
            if p.arch.qemu_name == "arm":
                # some stuff qira uses to determine the which libs to use for arm
                with open(self.binary_path, "rb") as f: progdata = f.read(0x800)
                if "/lib/ld-linux.so.3" in progdata:
                    directory = "armel"
                elif "/lib/ld-linux-armhf.so.3" in progdata:
                    directory = "armhf"

            if directory is None:
                l.warning("architecture \"%s\" has no installed libraries", p.arch.qemu_name)
            else:
                path = os.path.join(self.afl_dir, "..", "fuzzer-libs", directory)
        else:
            path = self.library_path

        if path is not None:
            l.debug("exporting QEMU_LD_PREFIX of '%s'", path)
            os.environ['QEMU_LD_PREFIX'] = path

    def _timer_callback(self):
        if self._stuck_callback is not None:
            # check if afl has pending fav's
            if ('fuzzer-master' in self.stats and 'pending_favs' in self.stats['fuzzer-master'] and \
               int(self.stats['fuzzer-master']['pending_favs']) == 0) or self.force_interval is not None:
                self._stuck_callback(self)

    def __del__(self):
        self.kill()
