import shellphish_afl
import logging
import os

l = logging.getLogger("phuzzer.phuzzers.afl")

from .afl import AFL
class AFLMultiCB(AFL):
    '''This is a multi-CB AFL phuzzer (for CGC).'''

    def __init__(self, targets, **kwargs):
        super().__init__(targets[0], **kwargs)
        self.afl_path = shellphish_afl.afl_bin('multi-cgc')
        self.afl_path_var = shellphish_afl.afl_path_var('multi-cgc')
        self.timeout = 1000 * len(targets)
        self.target_opts = targets[1:]

    def choose_afl(self):
        os.environ['AFL_PATH'] = shellphish_afl.afl_path_var('multi-cgc')
        return shellphish_afl.afl_bin('multi-cgc')
