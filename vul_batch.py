import subprocess
import json
import os
import sys
import time

firm_path = sys.argv[1]
res_dir = sys.argv[2]
typ = sys.argv[3]

st = time.time()

fven = open(res_dir+'/vendor.json','r')
vens = json.load(fven)
fven.close()

names = firm_path.split('/')
firm_name = names[-2]


if typ == 'bof':
    log_name = '/my_log_bof'
else:
    log_name = '/my_log_cmdi'

if os.path.exists(res_dir+log_name):
    with open(res_dir+log_name, 'r') as f:
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
    if '.so' in bname or '.ko' in bname or '.o' in bname:
        print('library')
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

    if not os.path.exists(res_dir+'/keywords.json'):
        with open(res_dir+'/keywords.json', "w+") as f:
            f.write("{}")


    command = []
    command += ['python','package/argument_resolver/analysis/my_mango.py',binpath]
    command += ["--results", bin_respath]
    command += ["--keyword-dict", res_dir+'/keywords.json']

    if typ == 'bof':
        command += ['--category','overflow']


    #print(binpath)
    print(command)
    #print(cm)
    
    ret_code = subprocess.call(command)
    print(ret_code)
    
    end = time.time()
    
    tt = end -start
    print(tt)

    try:
        with open(res_dir+log_name, 'a+') as f:
            f.write(binpath)
            f.write('\n')
            f.write(str(tt))
            f.write('\n')
    except:
        print(str(tt))
        print('error')
        continue
    print('end')

ed = time.time()
t = ed-st
with open(res_dir+log_name, 'a+') as f:
    f.write('my TIME: \n')
    f.write(str(t))
    f.write('\n')
