import subprocess
import json
import os
import sys
import time
from pathlib import Path

firm_path = sys.argv[1]
res_path = sys.argv[2]

firm_name = Path(firm_path).parent.name

print(firm_name)
res_dir = Path(res_path) / firm_name
if not os.path.exists(res_dir):
    os.mkdir(res_dir)


print('*'*30)
print('FIND ALL ELFs')
print('*'*30)

command = []
command += ['python','elf_finder/elf_finder.py',str(Path(firm_path).parent),str(res_dir)]

ret_code = subprocess.call(command)
print(ret_code)


print('*'*30)
print('PREPARE FOR IDA ANALYSIS')
print('*'*30)

command = []
command += ['python','for_pipe.py',str(Path(firm_path).parent),str(res_dir)]
print(command)

ret_code = subprocess.call(command)
print(ret_code)


rint('*'*30)
print('BACKTRACK VARIABLE WITH IDA')
print('*'*30)


command = []
command += ['python','variable_backtrack/batch.py',firm_path,str(res_dir / 'root')]
print(command)

ret_code = subprocess.call(command)
print(ret_code)


rint('*'*30)
print('DETECT VULNERABILITIES --- CMDI')
print('*'*30)


command = []
command += ['python','vul_batch.py',str(Path(firm_path).parent),str(res_dir),'cmdi']
print(command)

ret_code = subprocess.call(command)
print(ret_code)


rint('*'*30)
print('DETECT VULNERABILITIES --- BOF')
print('*'*30)

command = []
command += ['python','vul_batch.py',str(Path(firm_path).parent),str(res_dir),'bof']
print(command)

ret_code = subprocess.call(command)
print(ret_code)


rint('*'*30)
print('VERIFY SOURCES')
print('*'*30)

command = []
command += ['python','package/argument_resolver/analysis/find_gets.py',firm_path,str(res_dir)]
print(command)

ret_code = subprocess.call(command)
print(ret_code)


command = []
command += ['python','package/argument_resolver/analysis/envres.py',str(res_dir)]
print(command)

ret_code = subprocess.call(command)
print(ret_code)

rint('*'*30)
print('CALCULATE REUSLTS')
print('*'*30)


command = []
command += ['python','package/argument_resolver/analysis/result.py',str(res_dir)]
print(command)

ret_code = subprocess.call(command)
print(ret_code)


