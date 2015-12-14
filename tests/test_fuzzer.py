import nose
import tempfile
import subprocess
import fuzzer

import logging
l = logging.getLogger("fuzzer.tests.test_fuzzer")

import os
bin_location = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../../binaries'))
fuzzer_bin = str(os.path.join(os.path.dirname(os.path.realpath(__file__)), '../bin'))

def test_dictionary_creation_cgc():
    '''
    test dictionary creation on a binary
    '''

    binary = os.path.join(bin_location, "cgc_qualifier_event/cgc/ccf3d301_01")
    out_dict = tempfile.mktemp(prefix='fuzztest', dir='/tmp')

    args = [os.path.join(fuzzer_bin, 'create_dict.py'), binary, out_dict]

    p = subprocess.Popen(args)
    retcode = p.wait()

    nose.tools.assert_equal(retcode, 0)

    dict_data = open(out_dict).read()
    os.remove(out_dict)

    definitions = dict_data.split("\n")

    # assert we find just as definitions
    nose.tools.assert_true(len(definitions) >= 60)

def run_all():
    functions = globals()
    all_functions = dict(filter((lambda (k, v): k.startswith('test_')), functions.items()))
    for f in sorted(all_functions.keys()):
        if hasattr(all_functions[f], '__call__'):
            all_functions[f]()

if __name__ == "__main__":
    run_all()
