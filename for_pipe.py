import subprocess
import json
import os
import sys
import time
from pathlib import Path

_border_binaries = ['httpd', 'uhttpd', 'http', 'lighttpd', 'acos_service', 'pppd', 'rc', 'cupsd', 'upnp', 'upnpd',
                    'udhcpd', 'udhcpc', 'udhcp', 'net-cgi', 'telnet', 'telnetd', 'utelnetd']

firm_path = sys.argv[1]
res_dir = sys.argv[2]

names = firm_path.split('/')
firm_name = Path(firm_path).name
print(firm_name)

fven = open(res_dir + '/vendor.json', 'r')
vens = json.load(fven)
fven.close()

if not os.path.exists(Path(res_dir) / 'root'):
    os.mkdir(Path(res_dir) / 'root')

if os.path.exists(res_dir+'/for_log'):
    with open(res_dir+'/for_log', 'r') as f:
        cont = f.readlines()
else:
    cont = []


for ha in vens['elfs']:
    binpath = vens['elfs'][ha]['path']     
    print(binpath)
    start = time.time()
    
    bname = binpath.split('/')[-1]
    if binpath+'\n' in cont:
        print('already done')
        continue
        

    bin_respath = res_dir + '/root'
    short_binpath = binpath.split(firm_name)[1]
    names_on_path = short_binpath.split('/')[2:]
    for i in range(len(names_on_path)):
        bin_respath+='/'+names_on_path[i]
        if os.path.exists(bin_respath):
            continue
        else:
            os.mkdir(bin_respath)


    st = time.time()

    cm = []
    cm += ['python', 'package/argument_resolver/analysis/for_mango.py', binpath]
    # cm += ["--keyword-dict", str(keyword_dict)]
    # env_dict = pp + "/env.json"

    cm += ["--results", bin_respath]

    print(cm)

    try:
        ret_code = subprocess.call(cm)
    except:
        print('wrong')
        continue

        '''
        cm += ["--category", 'overflow']
        print(cm)
        try:
            ret_code = subprocess.call(cm)
        except:
            pass
        '''

    ed = time.time()

    with open(res_dir + 'for_log', 'a+') as flog:
        flog.write(binpath)
        flog.write('\n')
        flog.write(str(ed - st))
        flog.write('\n')
