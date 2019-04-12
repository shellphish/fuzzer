import os
import sys
import time
import random
import struct
import tempfile
import subprocess
import shellphish_qemu

from ..showmap import Showmap

import logging
l = logging.getLogger("fuzzer.extensions.Extender")

class Extender(object):

    def __init__(self, binary, sync_dir):

        self.binary = binary
        self.sync_dir = sync_dir

        self.current_fuzzer = None

        self.crash_count = 0
        self.test_count = 0

        self.name = self.__class__.__name__.lower()

        directories = [os.path.join(self.sync_dir, self.name),
                       os.path.join(self.sync_dir, self.name, "crashes"),
                       os.path.join(self.sync_dir, self.name, "queue"),
                       os.path.join(self.sync_dir, self.name, ".synced")]

        self.crash_bitmap = dict()

        for directory in directories:
            try:
                os.makedirs(directory)
            except OSError:
                continue

        l.debug("Fuzzer extension %s initialized", self.name)

    def _current_sync_count(self, fuzzer):
        """
        Get the current number of inputs belonging to `fuzzer` which we've already mutated.
        """

        sync_file = os.path.join(self.sync_dir, self.name, ".synced", fuzzer)
        if os.path.exists(sync_file):
            with open(sync_file, 'rb') as f:
                sc = struct.unpack("<I", f.read())[0]
            return sc

        return 0

    def _current_crash_sync_count(self, fuzzer):
        """
        Get the current number of inputs belonging to `fuzzer` which we've already mutated.
        """

        sync_file = os.path.join(self.sync_dir, self.name, ".synced", "%s-crashes" % fuzzer)
        if os.path.exists(sync_file):
            with open(sync_file, 'rb') as f:
                sc = struct.unpack("<I", f.read())[0]
            return sc

        return 0

    def _update_sync_count(self, fuzzer, n):
        """
        Update the sync count for a particular fuzzer.
        """

        sync_file = os.path.join(self.sync_dir, self.name, ".synced", fuzzer)

        raw_count = struct.pack("<I", n)
        with open(sync_file, 'wb') as f:
            f.write(raw_count)

    def _update_crash_sync_count(self, fuzzer, n):
        """
        Update the sync count for a particular fuzzer.
        """

        sync_file = os.path.join(self.sync_dir, self.name, ".synced", "%s-crashes" % fuzzer)

        raw_count = struct.pack("<I", n)
        with open(sync_file, 'wb') as f:
            f.write(raw_count)

    def _current_bitmap(self, fuzzer):

        bitmap_file = os.path.join(self.sync_dir, fuzzer, "fuzz_bitmap")
        if os.path.exists(bitmap_file):
            with open(bitmap_file, 'rb') as f:
                bitmap = f.read()
            return bitmap

        return None

    def _run_qemu(self, payload, args=None):

        qemu_path = shellphish_qemu.qemu_path("cgc-tracer")

        pargs  = [qemu_path]

        if isinstance(args, list):
            pargs += args

        pargs += ["-m", "8G"]

        pargs += [self.binary]

        with open("/dev/null", "wb") as devnull:
            p = subprocess.Popen(
                    pargs,
                    stdin=subprocess.PIPE,
                    stdout=devnull,
                    stderr=devnull)

            _, _ = p.communicate(payload)

        return p.wait()

    def _get_receive_counts(self, payload):

        lname = tempfile.mktemp(dir="/dev/shm/", prefix="receive-log-")

        _ = self._run_qemu(payload, ["-receive_count", lname])

        with open(lname, "r") as f:
            receive_counts = f.read()

        os.remove(lname)

        return [l.split() for l in receive_counts.split('\n')[:-1]]

    def _new_crash(self, payload):

        crash_dir = os.path.join(self.sync_dir, self.name, "crashes")

        path = "id:%06d,sig:11,src:%s,op:extending" % (self.crash_count, self.current_fuzzer)
        full_path = os.path.join(crash_dir, path)
        with open(full_path, 'wb') as f:
            f.write(payload)

        self.crash_count += 1

    def _new_test(self, payload):
        queue_dir = os.path.join(self.sync_dir, self.name, "queue")

        path = "id:%06d,src:%s,op:extending,+cov" % (self.test_count, self.current_fuzzer)
        full_path = os.path.join(queue_dir, path)
        with open(full_path, 'wb') as f:
            f.write(payload)

        self.test_count += 1

    def _interesting_crash(self, shownmap):

        interesting = False
        for i in shownmap.keys():

            if i not in self.crash_bitmap:
                interesting = True
                self.crash_bitmap[i] = shownmap[i]
            else:
                if shownmap[i] > self.crash_bitmap[i]:
                    interesting = True
                    self.crash_bitmap[i] = shownmap[i]

        return interesting

    @staticmethod
    def _interesting_test(shownmap, bitmap):

        for i in shownmap.keys():
            if shownmap[i] > (ord(bitmap[i]) ^ 0xff):
                return True

        return False

    def _submit_test(self, test_input, bitmap):

        sm = Showmap(self.binary, test_input)
        shownmap = sm.showmap()

        if sm.causes_crash and self._interesting_crash(shownmap):
            self._new_crash(test_input)
            l.info("Found a new crash (length %d)", len(test_input))
        elif not sm.causes_crash and self._interesting_test(shownmap, bitmap):
            self._new_test(test_input)
            l.info("Found an interesting new input (length %d)", len(test_input))
        else:
            l.debug("Found a dud")

    @staticmethod
    def _new_mutation(payload, extend_amount):

        def random_string(n):
            return bytes(random.choice(list(range(1, 9)) + list(range(11, 256))) for _ in range(n))

        np = payload + random_string(extend_amount + random.randint(0, 0x1000))
        l.debug("New mutation of length %d", len(np))

        return np

    def _mutate(self, r, bitmap):

        receive_counts = self._get_receive_counts(r)

        for numerator, denominator in receive_counts:
            if numerator != denominator:
                extend_by = denominator - numerator

                if extend_by > 1000000:
                    l.warning("Amount to extend is greater than 1,000,000, refusing to perform extension")
                    continue

                for _ in range(10):
                    test_input = self._new_mutation(r, extend_by)
                    self._submit_test(test_input, bitmap)

    def _do_round(self):
        """
        Single round of extending mutations.
        """

        def _extract_number(iname):
            attrs = dict(map(lambda x: (x[0], x[-1]), map(lambda y: y.split(":"), iname.split(","))))
            if "id" in attrs:
                return int(attrs["id"])
            return 0

        for fuzzer in os.listdir(self.sync_dir):
            if fuzzer == self.name:
                continue
            l.debug("Looking to extend inputs in fuzzer '%s'", fuzzer)

            self.current_fuzzer = fuzzer
            synced = self._current_sync_count(fuzzer)
            c_synced = self._current_crash_sync_count(fuzzer)

            l.debug("Already worked on %d inputs from fuzzer '%s'", synced, fuzzer)

            bitmap = self._current_bitmap(fuzzer)

            # no bitmap, fuzzer probably hasn't started
            if bitmap is None:
                l.warning("No bitmap for fuzzer '%s', skipping", fuzzer)
                continue

            queue_dir = os.path.join(self.sync_dir, fuzzer, "queue")

            queue_l = [n for n in os.listdir(queue_dir) if n != '.state']
            new_q = [i for i in queue_l if _extract_number(i) >= synced]

            crash_dir = os.path.join(self.sync_dir, fuzzer, "crashes")
            crash_l = [n for n in os.listdir(crash_dir) if n != 'README.txt']
            new_c = [i for i in crash_l if _extract_number(i) >= c_synced]
            new = new_q + new_c
            if len(new):
                l.info("Found %d new inputs to extend", len(new))

            for ninput in new_q:
                n_path = os.path.join(queue_dir, ninput)
                with open(n_path, "rb") as f:
                    self._mutate(f.read(), bitmap)

            for ninput in new_c:
                n_path = os.path.join(crash_dir, ninput)
                with open(n_path, "rb") as f:
                    self._mutate(f.read(), bitmap)

            self._update_sync_count(fuzzer, len(queue_l))
            self._update_crash_sync_count(fuzzer, len(crash_l))

    def run(self):

        while True:
            self._do_round()
            time.sleep(3)

if __name__ == "__main__":
    l.setLevel("INFO")

    if len(sys.argv) > 2:
        b = sys.argv[1]
        s = sys.argv[2]

        e = Extender(b, s)
        e.run()
    else:
        sys.exit(1)
