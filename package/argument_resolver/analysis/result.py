import os
import sys
import json
import sys

firm_path = sys.argv[1]

GET_FUNCS = ['getenv', 'nvram_get', 'acosNvramConfig_get', 'acosNvramConfig_read', 'j_nvram_get', 'nvram_get_str',
             'bcm_nvram_get', 'envram_get', 'wlcsm_nvram_get', 'dni_nvram_get', 'PIT_nvram_get', 'nvram_safe_get', 'GetValue']
SRC_FUNCS = ['fopen', 'read', "open", "fread", "fgets", "stdin", "socket", "accept", "recv", "nflog_get_payload",
             "frontend_param"]
HTTP_KEYS = ['Cookie', 'HTTP_COOKIE', 'HTTP_HOST', 'REQUEST_URI', 'CONTENT_TYPE', 'HTTP_REFERER', 'REMOTE_ADDR', 'HTTP_USER_AGENT']

res = {}

with open(firm_path+'/nvram_final.json', 'r') as f:
    nvram_final = json.load(f)

with open(firm_path+'/env_final.json', 'r') as f:
    env_final = json.load(f)

with open(firm_path+'/value_final.json', 'r') as f:
    value_final = json.load(f)

for root, dirs, files in os.walk(firm_path):
    for file in files:
        file_path = os.path.join(root, file)
        if file_path.endswith('cmdi_results.json'):
            print(file_path)
            res[file_path] = []
            with open(file_path, 'r') as f:
                cmdi_res = json.load(f)

            for trace in cmdi_res['closures']:
                key = trace['key string']
                rank = trace['rank']
                srcs = trace['sources_likely']
                src_strs = trace['inputs']['likely']
                sink = trace['sink']['function']

                if rank >= 7:
                    if trace not in res[file_path]:
                        res[file_path].append(trace)
                elif rank == 0:
                    continue
                else:
                    for src in srcs:
                        ss = srcs[src]
                        for s in ss:
                            if 'nvram' in s.lower():
                                if src in nvram_final:
                                    typee = nvram_final[src]['type']
                                else:
                                    typee = 'UNKNOW'
                            elif 'env' in s.lower():
                                if src in HTTP_KEYS:
                                    typee = 'VUL'
                                elif src in env_final:
                                    typee = env_final[src]['type']
                                else:
                                    typee = 'UNKNOW'
                            elif 'GetValue' in s:
                                if src in value_final:
                                    typee = value_final[src]['type']
                                else:
                                    typee = 'UNKNOW'
                            elif 'argv' in s.lower() or 'frontend_param' in s.lower() or 'recv' in s.lower():
                                typee = 'VUL'
                            else:
                                typee = 'CONST'
                            
                            if typee == 'UNKNOW':
                                if trace not in res[file_path]:
                                    res[file_path].append(trace)
                                break
                            if typee == 'VUL':
                                trace['rank'] = 7
                                if trace not in res[file_path]:
                                    res[file_path].append(trace)
                                break
                        if typee == 'VUL':
                            break
                
with open(firm_path + '/fffresult_cmdi.json', 'w') as jf:
    json.dump(res, jf, indent=4)


res = {}

with open(firm_path+'/nvram_final.json', 'r') as f:
    nvram_final = json.load(f)

with open(firm_path+'/env_final.json', 'r') as f:
    env_final = json.load(f)

with open(firm_path+'/value_final.json', 'r') as f:
    value_final = json.load(f)

for root, dirs, files in os.walk(firm_path):
    for file in files:
        file_path = os.path.join(root, file)
        if file_path.endswith('overflow_results.json'):
            print(file_path)
            res[file_path] = []
            with open(file_path, 'r') as f:
                cmdi_res = json.load(f)

            for trace in cmdi_res['closures']:
                key = trace['key string']
                rank = trace['rank']
                srcs = trace['sources_likely']
                src_strs = trace['inputs']['likely']
                sink = trace['sink']['function']

                if rank >= 7:
                    if trace not in res[file_path]:
                        res[file_path].append(trace)
                elif rank == 0:
                    continue
                else:
                    for src in srcs:
                        ss = srcs[src]
                        for s in ss:
                            if 'nvram' in s.lower():
                                if src in nvram_final:
                                    typee = nvram_final[src]['type']
                                else:
                                    typee = 'UNKNOW'
                            elif 'env' in s.lower():
                                if src in env_final:
                                    typee = env_final[src]['type']
                                else:
                                    typee = 'UNKNOW'
                            elif 'GetValue' in s:
                                if src in value_final:
                                    typee = value_final[src]['type']
                                else:
                                    typee = 'UNKNOW'
                            elif 'argv' in s.lower() or 'frontend_param' in s.lower() or 'recv' in s.lower():
                                typee = 'VUL'
                            else:
                                typee = 'CONST'
                            if typee == 'UNKNOW':
                                if trace not in res[file_path]:
                                    res[file_path].append(trace)
                                break
                            if typee == 'VUL':
                                trace['rank'] = 7
                                if trace not in res[file_path]:
                                    res[file_path].append(trace)
                                break
                        if typee == 'VUL':
                            break
                
with open(firm_path + '/fffresult_bof.json', 'w') as jf:
    json.dump(res, jf, indent=4)
