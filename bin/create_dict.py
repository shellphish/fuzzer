#!/usr/bin/env python

import sys
import angr
import string
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


def create(binary, outfile):

    b = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFGAccurate(keep_state=True)

    string_references = []
    for f in cfg.functions.values():
        try:
            string_references.append(f.string_references())
        except ZeroDivisionError:
            pass

    string_references = sum(string_references, [])
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

    with open(outfile, 'w') as f:
        for i, s in enumerate(set(valid_strings)):
            s_val = hexescape(s)
            f.write("string_%d=\"%s\"\n" % (i, s_val))

    return bool(len(valid_strings))


def main(argv):

    if len(argv) < 3:
        l.error("incorrect number of arguments passed to create_dict")
        print "usage: %s <binary> <output-dictionary>" % sys.argv[0]
        return 1

    binary = argv[1]
    outfile = argv[2]

    return int(not create(binary, outfile))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
