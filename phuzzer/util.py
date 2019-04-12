import string
import os

def hexescape(s):
    '''
    perform hex escaping on a raw string s
    '''

    out = []
    acceptable = (string.ascii_letters + string.digits + " .").encode()
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % c)
        else:
            out.append(chr(c))

    return ''.join(out)

def _get_bindir():
    base = os.path.dirname(__file__)
    while not "bin" in os.listdir(base) and os.path.abspath(base) != "/":
        base = os.path.join(base, "..")
    if os.path.abspath(base) == "/":
        raise InstallError("could not find afl install directory")
    return base

from .errors import InstallError
