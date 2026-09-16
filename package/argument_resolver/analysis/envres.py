import json
import sys
import os

firm_path = sys.argv[1]

res = {}
unsolve = {}

for root, dirs, files in os.walk(firm_path):
    for file in files:
        file_path = os.path.join(root, file)
        if file_path.endswith('env_results.json'):
            print(file_path)
            with open(file_path, 'r') as f:
                env_info = json.load(f)
            for trace in env_info['closures']:
                key = trace['key string']
                rank = trace['rank']
                src = trace['sources_likely']
                sink = trace['sink']['function']
                if 'env' not in sink.lower():
                    continue
                if rank >= 7:
                    type = 'VUL'
                    if key not in res:
                        res[key] = {}
                        res[key]['type'] = type
                        res[key]['source'] = src
                elif rank == 0:
                    type = 'CONST'
                    if key not in res:
                        res[key] = {}
                        res[key]['type'] = type
                        res[key]['source'] = src
                else:
                    if len(trace['sources_likely']) == 0:
                        type = 'CONST'
                    else:
                        src_keys = trace['inputs']['likely']
                        type = 'UNKNOW'
                        src = []
                        for sk in src_keys:
                            if sk in res:
                                t = res[sk]['type']
                                if t == 'VUL':
                                    type = 'VUL'
                                    src = res[sk]['source']
                                    break
                                else:
                                    type = t
                                    continue
                        if type == 'UNKNOW':
                            if key not in unsolve:
                                unsolve[key] = src_keys
                        else:
                            if key not in res:
                                res[key] = {}
                                res[key]['type'] = type
                                res[key]['source'] = src

unsolve_1 = {}
for us in unsolve:
    type = 'UN'
    src = []
    src_keys = unsolve[us]
    for sk in src_keys:
        if sk in res:
            t = res[sk]['type']
            if t == 'VUL':
                type = 'VUL'
                src = res[sk]['source']
                break
            else:
                type = t
                continue
    if type == 'UN':
        unsolve_1[key] = src_keys
    else:
        if key not in res:
            res[key] = {}
            res[key]['type'] = type
            res[key]['source'] = src


for us in unsolve_1:
    type = 'UN'
    src = []
    src_keys = unsolve_1[us]
    for sk in src_keys:
        if sk in res:
            t = res[sk]['type']
            if t == 'VUL':
                type = 'VUL'
                src = res[sk]['source']
                break
            else:
                type = t
                continue
    if type == 'UN':
        res[key] = {}
        res[key]['type'] = 'UNKNOW'
        res[key]['source'] = src
    else:
        if key not in res:
            res[key] = {}
            res[key]['type'] = type
            res[key]['source'] = src

res_path = firm_path
with open(res_path + '/env_final.json', 'w') as jf:
    json.dump(res, jf, indent=4)


res = {}
unsolve = {}

for root, dirs, files in os.walk(firm_path):
    for file in files:
        file_path = os.path.join(root, file)
        if file_path.endswith('env_results.json'):
            print(file_path)
            with open(file_path, 'r') as f:
                env_info = json.load(f)
            for trace in env_info['closures']:
                key = trace['key string']
                rank = trace['rank']
                src = trace['sources_likely']
                sink = trace['sink']['function']
                if 'nvram' not in sink.lower():
                    continue
                if rank >= 7:
                    type = 'VUL'
                    if key not in res:
                        res[key] = {}
                        res[key]['type'] = type
                        res[key]['source'] = src
                elif rank == 0:
                    type = 'CONST'
                    if key not in res:
                        res[key] = {}
                        res[key]['type'] = type
                        res[key]['source'] = src
                else:
                    if len(trace['sources_likely']) == 0:
                        type = 'CONST'
                    else:
                        src_keys = trace['inputs']['likely']
                        type = 'UNKNOW'
                        src = []
                        for sk in src_keys:
                            if sk in res:
                                t = res[sk]['type']
                                if t == 'VUL':
                                    type = 'VUL'
                                    src = res[sk]['source']
                                    break
                                else:
                                    type = t
                                    continue
                        if type == 'UNKNOW':
                            if key not in unsolve:
                                unsolve[key] = src_keys
                        else:
                            if key not in res:
                                res[key] = {}
                                res[key]['type'] = type
                                res[key]['source'] = src

unsolve_1 = {}
for us in unsolve:
    type = 'UN'
    src = []
    src_keys = unsolve[us]
    for sk in src_keys:
        if sk in res:
            t = res[sk]['type']
            if t == 'VUL':
                type = 'VUL'
                src = res[sk]['source']
                break
            else:
                type = t
                continue
    if type == 'UN':
        unsolve_1[key] = src_keys
    else:
        if key not in res:
            res[key] = {}
            res[key]['type'] = type
            res[key]['source'] = src


for us in unsolve_1:
    type = 'UN'
    src = []
    src_keys = unsolve_1[us]
    for sk in src_keys:
        if sk in res:
            t = res[sk]['type']
            if t == 'VUL':
                type = 'VUL'
                src = res[sk]['source']
                break
            else:
                type = t
                continue
    if type == 'UN':
        res[key] = {}
        res[key]['type'] = 'UNKNOW'
        res[key]['source'] = src
    else:
        if key not in res:
            res[key] = {}
            res[key]['type'] = type
            res[key]['source'] = src


res_path = firm_path
with open(res_path + '/nvram_final.json', 'w') as jf:
    json.dump(res, jf, indent=4)


res = {}
unsolve = {}

for root, dirs, files in os.walk(firm_path):
    for file in files:
        file_path = os.path.join(root, file)
        if file_path.endswith('env_results.json'):
            print(file_path)
            with open(file_path, 'r') as f:
                env_info = json.load(f)
            for trace in env_info['closures']:
                key = trace['key string']
                rank = trace['rank']
                src = trace['sources_likely']
                sink = trace['sink']['function']
                if 'value' not in sink.lower():
                    continue
                if rank >= 7:
                    type = 'VUL'
                    if key not in res:
                        res[key] = {}
                        res[key]['type'] = type
                        res[key]['source'] = src
                elif rank == 0:
                    type = 'CONST'
                    if key not in res:
                        res[key] = {}
                        res[key]['type'] = type
                        res[key]['source'] = src
                else:
                    if len(trace['sources_likely']) == 0:
                        type = 'CONST'
                    else:
                        src_keys = trace['inputs']['likely']
                        type = 'UNKNOW'
                        src = []
                        for sk in src_keys:
                            if sk in res:
                                t = res[sk]['type']
                                if t == 'VUL':
                                    type = 'VUL'
                                    src = res[sk]['source']
                                    break
                                else:
                                    type = t
                                    continue
                        if type == 'UNKNOW':
                            if key not in unsolve:
                                unsolve[key] = src_keys
                        else:
                            if key not in res:
                                res[key] = {}
                                res[key]['type'] = type
                                res[key]['source'] = src

unsolve_1 = {}
for us in unsolve:
    type = 'UN'
    src = []
    src_keys = unsolve[us]
    for sk in src_keys:
        if sk in res:
            t = res[sk]['type']
            if t == 'VUL':
                type = 'VUL'
                src = res[sk]['source']
                break
            else:
                type = t
                continue
    if type == 'UN':
        unsolve_1[key] = src_keys
    else:
        if key not in res:
            res[key] = {}
            res[key]['type'] = type
            res[key]['source'] = src


for us in unsolve_1:
    type = 'UN'
    src = []
    src_keys = unsolve_1[us]
    for sk in src_keys:
        if sk in res:
            t = res[sk]['type']
            if t == 'VUL':
                type = 'VUL'
                src = res[sk]['source']
                break
            else:
                type = t
                continue
    if type == 'UN':
        res[key] = {}
        res[key]['type'] = 'UNKNOW'
        res[key]['source'] = src
    else:
        if key not in res:
            res[key] = {}
            res[key]['type'] = type
            res[key]['source'] = src


res_path = firm_path
with open(res_path + '/value_final.json', 'w') as jf:
    json.dump(res, jf, indent=4)
