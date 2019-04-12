#!/usr/bin/env python

import os
import sys
import tqdm
import json
import phuzzer

DIR = sys.argv[1].rstrip('/')
BIN = os.path.basename(DIR).split('-')[-1]
print(DIR,BIN)
f = phuzzer.Phuzzer('/results/bins/%s'%BIN, '', job_dir=DIR)
h = phuzzer.InputHierarchy(fuzzer=f, load_crashes=True)

def good(_i):
    return _i.instance not in ('fuzzer-1', 'fuzzer-2', 'fuzzer-3', 'fuzzer-4', 'fuzzer-5')

all_blocks = set()
all_transitions = set()
all_inputs = [ i for i in h.inputs.values() if not i.crash and good(i) ]
all_crashes = [ i for i in h.inputs.values() if i.crash ]
min_timestamp = min(i.timestamp for i in all_inputs)
if all_crashes:
    first_crash = min(all_crashes, key=lambda i: i.timestamp)
    time_to_crash = first_crash.timestamp - min_timestamp
    first_crash_techniques = first_crash.contributing_techniques
    if 'grease' in first_crash_techniques :
        # TODO: figure out how long that input took
        time_to_crash += 120
else:
    first_crash = None
    time_to_crash = -1
    first_crash_techniques = set()

for i in tqdm.tqdm(all_inputs):
    all_blocks.update(i.block_set)
    all_transitions.update(i.transition_set)

fuzzer_only = { i for i in all_inputs if list(i.contributing_techniques) == ['fuzzer'] }
grease_derived = { i for i in all_inputs if 'grease' in i.contributing_techniques }
driller_derived = { i for i in all_inputs if 'driller' in i.contributing_techniques }
hybrid_derived = grease_derived & driller_derived
#tc = h.technique_contributions()

tag = ''.join(DIR.split('/')[-1].split('-')[:-2])

results = {
    'bin': BIN,
    'tag': tag,
    'testcase_count': len(all_inputs),
    'crash_count': len(all_crashes),
    'crashed': len(all_crashes)>0,
    'crash_time': time_to_crash,
    'crash_techniques': tuple(first_crash_techniques),
    'grease_assisted_crash': 'grease' in first_crash_techniques,
    'driller_assisted_crash': 'driller' in first_crash_techniques,
    'fuzzer_assisted_crash': 'fuzzer' in first_crash_techniques,
    'fuzzer_only_testcases': len(fuzzer_only),
    'greese_derived_testcases': len(grease_derived),
    'driller_derived_testcases': len(driller_derived),
    'hybrid_derived_testcases': len(hybrid_derived),
    'blocks_triggered': len(all_blocks),
    'transitions_triggered': len(all_transitions),
}

print("")
for k,v in results.items():
    print("RESULT", results['tag'], results['bin'], k, v)
print("")
print("JSON", json.dumps(results))

#print("RESULT",tag,BIN,": fuzzer blocks:",tc.get('fuzzer', (0,0))[0])
#print("RESULT",tag,BIN,": driller blocks:",tc.get('driller', (0,0))[0])
#print("RESULT",tag,BIN,": grease blocks:",tc.get('grease', (0,0))[0])
#print("RESULT",tag,BIN,": fuzzer crashes:",tc.get('fuzzer', (0,0))[1])
#print("RESULT",tag,BIN,": driller crashes:",tc.get('driller', (0,0))[1])
#print("RESULT",tag,BIN,": grease crashes:",tc.get('grease', (0,0))[1])
