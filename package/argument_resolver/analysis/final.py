import subprocess
import os
import sys
import re
import json
import itertools
import regex
import sys

sys.path.append('/home/zc/operation-mango-public/package')
from argument_resolver.utils.rank import categories, tag_values


ENV_FUNCS = ['getenv', 'nvram_get', 'acosNvramConfig_get', 'acosNvramConfig_read', 'j_nvram_get', 'nvram_get_str',
             'bcm_nvram_get', 'envram_get', 'wlcsm_nvram_get', 'dni_nvram_get', 'PIT_nvram_get', 'nvram_safe_get']
SRC_FUNCS = ['fopen', 'read', "open", "fread", "fgets", "stdin", "socket", "accept", "recv", "nflog_get_payload",
             "frontend_param"]
HTTP_KEYS = ['Cookie', 'HTTP_COOKIE', 'HTTP_HOST']


def extract_value(val):
    ret = []
    if val['constant'] is not None:
        for v in val['constant']:
            if v not in ret:
                ret.append(v)
    if val['source'] is not None:
        for func, v in val['source']:
            if v not in ret:
                ret.append(v)
    return ret


def del_quote(s):
    if s[0] == '\"' and s[-1] == '\"':
        return s[1:-1]


res_path = sys.argv[1]
final = {}

for root, dirs, files in os.walk(res_path):
    for file in files:
        if file == 'found_setters':
            file_path = os.path.join(root, file)
            print(file_path)
        lines = []
        try:
            with open(file_path, 'r') as f:
                lines = f.readlines()
        except:
            continue
        setters = eval(lines[1])
        execs = eval(lines[3])

        for setter in setters:
            if setter not in final:
                final[setter] = {}
            for addr in setters[setter]:
                for keyw in setters[setter][addr]:
                    vals = setters[setter][addr][keyw]
                    if keyw not in final[setter]:
                        final[setter][keyw] = []
                    if vals not in final[setter][keyw]:
                        try:
                            temp = final[setter][keyw] + vals
                            temp = list(set(temp))
                        except:
                            temp = final[setter][keyw] + vals[0]
                            temp = list(set(temp))
                        final[setter][keyw] = temp

        for exe in execs:
            if exe not in final:
                final[exe] = {}
            for addr in execs[exe]:
                for dic in execs[exe][addr]:
                    for env in dic['constant']:
                        if '=' in env:
                            keyw = env.split('=')[0]
                            val = env.split('=')[1]
                            if keyw not in final[exe]:
                                final[exe][keyw] = []
                            if val not in final[exe][keyw]:
                                final[exe][keyw].append(val)

for func in final:
    for kw in final[func]:
        vals = final[func][kw]
        if vals == 'constant' or vals == 'unknown':
            continue
        vul = False
        unknow = False
        for v in vals:
            if v == 'unknown':
                unknow = True
            if v!= 'unknown':
                unknow = False
            matches = regex.findall(r'(\w+)\(((?:[^()]++|(?R))*)\)', v)
            if len(matches) > 0:
                vul = True
                break
        if not vul:
            if unknow:
                final[func][kw] = 'unknown'
            else:
                final[func][kw] = 'constant'

for func in final:
    for kw in final[func]:
        vals = final[func][kw]
        if kw in HTTP_KEYS:
            final[func][kw] = 'vulnerable'
            continue
        if vals == 'constant' or vals == 'unknown':
            continue
        for v in vals:
            matches = regex.findall(r'(\w+)\(((?:[^()]++|(?R))*)\)', v)
            for f, arg in matches:
                ff = f.lower()
                ff = 'recv' if 'recv' in ff else ff
                for c, fcs in categories.items():
                    if c == 'env':
                        continue
                    if ff in fcs:
                        final[func][kw] = 'vulnerable'

# with open(set_info+'final3.json','r') as f:
#    final = json.load(f)

for iii in range(3):
    for func in final:
        for kw in final[func]:
            vals = final[func][kw]
            unknow = False
            vul = False
            constant = False

            if vals == 'constant' or vals == 'vulnerable' or vals == 'unknown':
                continue

            for v in vals:
                matches = regex.findall(r'(\w+)\(((?:[^()]++|(?R))*)\)', v)
                for f, arg in matches:
                    if f in ENV_FUNCS:
                        setf = f.replace('get', 'set')
                        if setf == func and del_quote(arg) == kw:
                            unknow = True
                            continue
                        try:
                            setv = final[setf][del_quote(arg)]
                            if setv == 'constant':
                                unknow = False
                                constant = True
                            elif setv == 'vulnerable':
                                unknow = False
                                constant = False
                                vul = True
                            elif setv == 'unknown':
                                unknow = True
                            else:
                                unknow = False
                                constant = False
                                for j in setv:
                                    _matches = regex.findall(r'(\w+)\(((?:[^()]++|(?R))*)\)', j)
                                    for _f, _arg in _matches:
                                        if _f.replace('get', 'set') == func and del_quote(_arg) == kw:
                                            unknow = True
                        except:
                            unknow = True
                            continue
            if vul:
                final[func][kw] = 'vulnerable'
            elif unknow:
                final[func][kw] = 'unknown'
            elif constant:
                final[func][kw] = 'constant'
            else:
                pass

with open(res_path + 'final.json', 'w') as jf:
    json.dump(final, jf, indent=4)
