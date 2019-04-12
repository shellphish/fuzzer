import os
import shutil
import logging
from .. import Showmap

l = logging.getLogger("grease_callback")

class GreaseCallback(object):
    def __init__(self, grease_dir, grease_filter=None, grease_sorter=None):
        self._grease_dir = grease_dir
        assert os.path.exists(grease_dir)
        self._grease_filter = grease_filter if grease_filter is not None else lambda x: True
        self._grease_sorter = grease_sorter if grease_sorter is not None else lambda x: x

    def grease_callback(self, fuzz):
        l.warning("we are stuck, trying to grease the wheels!")

        # find an unused input
        grease_inputs = [
            os.path.join(self._grease_dir, x) for x in os.listdir(self._grease_dir)
            if self._grease_filter(os.path.join(self._grease_dir, x))
        ]

        if len(grease_inputs) == 0:
            l.warning("no grease inputs remaining")
            return

        # iterate until we find one with a new bitmap
        bitmap = fuzz.bitmap()
        for a in self._grease_sorter(grease_inputs):
            if os.path.getsize(a) == 0:
                continue
            with open(a) as sf:
                seed_content = sf.read()
            smap = Showmap(fuzz.binary_path, seed_content)
            shownmap = smap.showmap()
            for k in shownmap:
                #print(shownmap[k], (ord(bitmap[k % len(bitmap)]) ^ 0xff))
                if shownmap[k] > (ord(bitmap[k % len(bitmap)]) ^ 0xff):
                    l.warning("Found interesting, syncing to tests")

                    fuzzer_out_dir = fuzz.out_dir
                    grease_dir = os.path.join(fuzzer_out_dir, "grease")
                    grease_queue_dir = os.path.join(grease_dir, "queue")
                    try:
                        os.mkdir(grease_dir)
                        os.mkdir(grease_queue_dir)
                    except OSError:
                        pass
                    id_num = len(os.listdir(grease_queue_dir))
                    filepath = "id:" + ("%d" % id_num).rjust(6, "0") + ",grease"
                    filepath = os.path.join(grease_queue_dir, filepath)
                    shutil.copy(a, filepath)
                    l.warning("copied grease input: %s", os.path.basename(a))
                    return

        l.warning("No interesting inputs found")
    __call__ = grease_callback
