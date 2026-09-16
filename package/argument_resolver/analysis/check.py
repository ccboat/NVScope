import subprocess
import os
import sys
import re
import json
import csv

import sys

sys.path.append('/home/zc/operation-mango-public/package')
from argument_resolver.utils.rank import categories

ENV_FUNCS = ['getenv', 'nvram_get', 'acosNvramConfig_get', 'acosNvramConfig_read', 'j_nvram_get', 'nvram_get_str',
             'bcm_nvram_get', 'envram_get', 'wlcsm_nvram_get', 'dni_nvram_get', 'PIT_nvram_get', 'nvram_safe_get',
             'httpGetEnv', 'GetValue']

web_words = ['HTTP_COOKIE', 'HTTP_HOST', 'HNAP_AUTH', 'REQUEST_URI', 'CONTENT_TYPE', 'PATH']
setters = ['setenv', 'script_setenv', 'nvram_set', 'acosNvramConfig_set', 'acosNvramConfig_write', 'j_nvram_set',
           'nvram_set_str', 'bcm_nvram_set', 'envram_set', 'wlcsm_nvram_set', 'dni_nvram_set', 'PIT_nvram_set',
           'nvram_safe_set', 'httpSetEnv', 'SetValue']


def find_env(keyword, getname, setinfo):
    if keyword in web_words:
        return 'vulnerable'
    with open(setinfo, 'r') as f:
        info = json.load(f)

    if 'get' in getname:
        setname = getname.replace('get','set')
    elif 'read' in getname:
        setname = getname.replace('read','write')
    elif 'Get' in getname:
        setname = getname.replace('Get', 'Set')
    else:
        print('wrong name')
        print(getname)
        return None

    try:
        state = info[setname][keyword]
    except:
        if keyword in info['execve']:
            state = info['execve'][keyword]
        elif keyword in info['execle']:
            state = info['execle'][keyword]
        else:
            if 'nvram' in setname.lower():
                states = []
                for sname in info:
                    if 'nvram' in sname:
                        try:
                            state = info[sname][keyword]
                            states.append(state)
                        except:
                            state = 'notset'
                            states.append(state)
                if len(states) == 0:
                    state = 'notset'
                else:
                    rank = 0
                    for s in states:
                        if s == 'vulnerable':
                            rank += 7
                        if s == 'constant':
                            rank += 0
                        if s == 'unknown':
                            rank += 5
                    rank = rank / len(states)
                    if rank <= 3:
                        state = 'constant'
                    elif rank < 6:
                        state = 'unknown'
                    else:
                        state = 'vulnerable'
            else:
                state = 'notset'
    return state


def deal_result(result, setinfo):
    for trace in result['closures']:
        if trace['rank'] == 0:
            continue
        if len(trace['inputs']['likely']) == 0:
            continue
        if trace['sink']['function'] in setters:
            continue
        source = trace['sources_likely']
        states = []
        for kw in source:
            src_funcs = source[kw]
            for sfun in src_funcs:
                sfuname = sfun.split('(')[0]
                if sfuname in ENV_FUNCS:
                    state = find_env(kw, sfuname, setinfo)
                    states.append(state)
        if len(states)>0:
            if 'vulnerable' in states:
                trace['rank'] = 7
            elif 'unknown' in states:
                trace['rank'] = 5
            elif 'notset' in states:
                trace['rank'] = 3
            else:
                trace['rank'] = 0.7
    return result


def write_csv_result(binpath, typ, ori_res, my_res, respath):
    csvfile = open(respath + 'output.csv', 'a+', newline='')
    writer = csv.writer(csvfile)
    # writer.writerow(['Filename','Type','SinkAddr','SrcAddr','Keyword','Mango','My','source'])
    for i in range(len(ori_res['closures'])):
        otrace = ori_res['closures'][i]
        mtrace = my_res['closures'][i]
        if otrace['sink']['function'] in setters:
            continue
        writer.writerow(
            [binpath, typ, otrace['sink']['ins_addr'], otrace['trace'][0]['ins_addr'], otrace['inputs']['likely'],
             otrace['sink']['function'], mtrace['rank'], otrace['sources_likely']])

    csvfile.close()


res_path = sys.argv[1]
set_info = res_path + 'final.json'
filepa = res_path + 'squashfs-root/'

fven = open(res_path + 'vendor.json', 'r')
vens = json.load(fven)
fven.close()

for ha in vens['elfs']:
    binpath = vens['elfs'][ha]['path']
    bname = binpath.split('squashfs-root')[-1]
    brespa = filepa + bname

    if os.path.exists(brespa + '/cmdi_results.json'):
        with open(brespa + '/cmdi_results.json', 'r') as f:
            cmd_res = json.load(f)
        res = deal_result(cmd_res, set_info)
        with open(brespa + '/cmdi_results.json', 'r') as f:
            cmd_res = json.load(f)
        write_csv_result(bname, 'cmdi', cmd_res, res, res_path)

    if os.path.exists(brespa+'/overflow_results.json'):
        with open(brespa+'/overflow_results.json','r') as f:
            bof_res = json.load(f)
        #res = deal_result(bof_res, set_info)
        with open(brespa+'/overflow_results.json','r') as f:
            bof_res = json.load(f)
        write_csv_result(bname, 'overflow', bof_res, bof_res, res_path)


