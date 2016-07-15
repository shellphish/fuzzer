#!/usr/bin/env python

import os
import sys
import angr
import string
import itertools

import logging

l = logging.getLogger("create_dict")


def hexescape(s):
    '''
    perform hex escaping on a raw string s
    '''

    out = []
    acceptable = string.letters + string.digits + " ."
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % ord(c))
        else:
            out.append(c)

    return ''.join(out)


strcnt = itertools.count()

def create(binary):

    b = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFG(resolve_indirect_jumps=True, collect_data_references=True)

    state = b.factory.blank_state()

    string_references = []
    for v in cfg._memory_data.values():
        if v.sort == "string" and v.size > 1:
            st = state.se.any_str(state.memory.load(v.address, v.size))
            string_references.append((v.address, st))

    strings = [] if len(string_references) == 0 else zip(*string_references)[1]

    valid_strings = []
    if len(strings) > 0:
        for s in strings:
            if len(s) <= 128:
                valid_strings.append(s)
            for s_atom in s.split():
                # AFL has a limit of 128 bytes per dictionary entries
                if len(s_atom) <= 128:
                    valid_strings.append(s_atom)

    for s in set(valid_strings):
        s_val = hexescape(s)
        print "string_%d=\"%s\"" % (strcnt.next(), s_val)


def main(argv):

    if len(argv) < 2:
        l.error("incorrect number of arguments passed to create_dict")
        print "usage: %s [binary1] [binary2] [binary3] ... " % sys.argv[0]
        return 1

    for binary in argv[1:]:
        if os.path.isfile(binary):
            create(binary)

    return int(strcnt.next() == 0)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
