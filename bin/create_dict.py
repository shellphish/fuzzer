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

    out = [ ]
    acceptable = string.letters + string.digits + " ."
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % ord(c))
        else:
            out.append(c)

    return ''.join(out)

def create(binary, outfile):

    b = angr.Project(binary, load_options={'auto_load_libs': False})
    cfg = b.analyses.CFG(keep_input_state=True)

    string_references = [ ]
    for f in cfg.function_manager.functions.values():
        try:
            string_references.append(f.string_references())
        except ZeroDivisionError:
            pass

    string_references = sum(string_references, [])

    strings = [] if len(string_references) == 0 else zip(*string_references)[1]

    valid_strings = filter(lambda s: len(s) <= 128 and len(s) > 0, strings)
    if len(valid_strings) > 0:
        with open(outfile, 'wb') as f:
            for i, s in enumerate(valid_strings):
                # AFL has a limit of 128 bytes per dictionary entries
                if len(s) <= 128:
                    esc_s = hexescape(s)
                    f.write("string_%d=\"%s\"\n" % (i, esc_s))

        return True

    return False

def main(argv):

    if len(argv) < 3:
        l.error("incorrect number of arguments passed to create_dict")
        return 1

    binary  = argv[1]
    outfile = argv[2]

    return int(not create(binary, outfile))

if __name__ == "__main__":
    sys.exit(main(sys.argv))
