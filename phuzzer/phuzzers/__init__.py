import shellphish_afl
import subprocess
import distutils.spawn #pylint:disable=no-name-in-module,import-error
import logging
import signal
import shutil
import time
import angr
import sys
import os

l = logging.getLogger("phuzzer.phuzzers")

class Phuzzer:
    ''' Phuzzer object, spins up a fuzzing job on a binary '''

    def __init__(self, target, seeds=None, dictionary=None, create_dictionary=False):
        '''
        :param target: the target (i.e., path to the binary to fuzz, or a docker target)
        :param seeds: list of inputs to seed fuzzing with
        :param dictionary: a list of bytes objects to seed the dictionary with
        :param create_dictionary: create a dictionary from the string references in the binary
        '''

        self.target = target
        self.seeds = seeds or [ ]

        # processes spun up
        self.processes            = [ ]

        self.start_time = None
        self.end_time = None

        self.check_environment()

        # token dictionary
        self.dictionary = dictionary or (self.create_dictionary() if create_dictionary else [])

    #
    # Some convenience functionality.
    #

    def found_crash(self):
        return len(self.crashes()) > 0

    def add_cores(self, n):
        for _ in range(n):
            self.add_core()

    def remove_cores(self, n):
        '''
        remove multiple fuzzers
        '''
        for _ in range(n):
            self.remove_core()

    def start(self):
        self.start_time = int(time.time())
        return self
    __enter__ = start

    def stop(self):
        self.end_time = int(time.time())
        if self.start_time is not None:
            l.info("Phuzzer %s shut down after %d seconds.", self, self.end_time - self.start_time)
        for p in self.processes:
            p.terminate()
            p.wait()
    __exit__ = stop

    @classmethod
    def check_environment(cls):
        try:
            cls._check_environment()
        except InstallError as e:
            tmp = ""
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "############# ATTENTION: YOUR SYSTEM IS MISCONFIGURED FOR FUZZING #############\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "####### THE FUZZER WILL NOT RUN. AND IT IS ***YOUR FAULT***!!!!!!!!!!!!  ######\n"
            tmp += "####### DIRECTLY BELOW THIS, THERE ARE CONCRETE REASONS FOR WHY THIS IS  ######\n"
            tmp += "####### IF YOU COMPLAIN TO US ON GITHUB ABOUT THIS NOT WORKING, AND YOU  ######\n"
            tmp += "####### DON'T RESOLVE THESE ISSUES FIRST, WE WILL NOT HELP YOU!!!!!!!!!  ######\n"
            tmp += "####### PLEASE RESOLVE THE ISSUES BELOW.    THEY LITERALLY TELL YOU WHAT ######\n"
            tmp += "####### YOU HAVE TO EXECUTE. DO NOT ASK FOR HELP IF YOU ARE SEEING THIS  ######\n"
            tmp += "####### MESSAGE; JUST FIX THE PROBLEM WITH YOUR SYSTEM!!!!!!!!!!!!!!!!!  ######\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += e.args[0]
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "####### FIX THE ABOVE ISSUES BEFORE ASKING FOR HELP. THE TEXT LITERALLY  ######\n"
            tmp += "####### TELLS YOU HOW TO DO IT. DO NOT ASK FOR HELP ABOUT THIS BEFORE    ######\n"
            tmp += "####### FIXING THE ABOVE ISSUES. IF YOU ARE SEEING THIS MESSAGE, YOUR    ######\n"
            tmp += "####### SYSTEM MISCONFIGURATION IS *******YOUR FAULT*********!!!!!!!!!!! ######\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            tmp += "#######                                                                  ######\n"
            tmp += "#######                                                                  ######\n"
            tmp += "#######                GET YOUR SYSTEM SETUP FIXED!!!!!!!!!!             ######\n"
            tmp += "#######                                                                  ######\n"
            tmp += "#######                                                                  ######\n"
            tmp += "###############################################################################\n"
            tmp += "###############################################################################\n"
            e.args = (tmp,)
            xmsg = distutils.spawn.find_executable("xmessage") #pylint:disable=no-member
            if xmsg:
                subprocess.Popen([xmsg, tmp]).wait()
            l.critical(tmp)
            print(tmp)
            sys.stderr.write(tmp)
            sys.stdout.write(tmp)
            raise


    #
    # Dictionary creation
    #

    def create_dictionary(self):
        l.warning("creating a dictionary of string references within target \"%s\"", self.target)

        b = angr.Project(self.target, load_options={'auto_load_libs': False})
        cfg = b.analyses.CFG(resolve_indirect_jumps=True, collect_data_references=True)
        state = b.factory.blank_state()

        string_references = []
        for v in cfg._memory_data.values():
            if v.sort == "string" and v.size > 1:
                st = state.solver.eval(state.memory.load(v.address, v.size), cast_to=bytes)
                string_references.append((v.address, st))

        strings = [] if len(string_references) == 0 else list(list(zip(*string_references))[1])
        return strings


    #
    # Subclasses should override this.
    #

    @staticmethod
    def _check_environment():
        raise NotImplementedError()

    def crashes(self, signals=(signal.SIGSEGV, signal.SIGILL)):
        """
        Retrieve the crashes discovered by AFL. Since we are now detecting flag
        page leaks (via SIGUSR1) we will not return these leaks as crashes.
        Instead, these 'crashes' can be found with the leaks function.

        :param signals: list of valid kill signal numbers to override the default (SIGSEGV and SIGILL)
        :return: a list of strings which are crashing inputs
        """
        raise NotImplementedError()

    def queue(self, fuzzer='fuzzer-master'):
        '''
        retrieve the current queue of inputs from a fuzzer
        :return: a list of strings which represent a fuzzer's queue
        '''
        raise NotImplementedError()

    def pollenate(self, *testcases):
        '''
        pollenate a fuzzing job with new testcases

        :param testcases: list of bytes objects representing new inputs to introduce
        '''
        raise NotImplementedError()

    def add_core(self):
        raise NotImplementedError()

    def remove_core(self):
        raise NotImplementedError()

    def __del__(self):
        self.stop()

from ..errors import InstallError
from .afl import AFL
from .afl_multicb import AFLMultiCB
