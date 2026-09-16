import sys
import re

p=sys.argv[1]
ida = p + 'ida_log'
cmdi = p + 'my_log_cmdi'
bof = p + 'my_log_bof'
env = p + 'env_log'
forr = p + 'for_log'

for_time = 0
try:
    with open(forr, 'r') as file:
        for line in file:
            if re.search("[a-zA-Z]", line):
                continue
            else:
                for_time += float(line.strip())
except:
    print('for error')


ida_time = 0
try:
    with open(ida, 'r') as file:
        for line in file:
            if re.search("[a-zA-Z]", line):
                continue
            else:
                ida_time += float(line.strip())
except:
    print('ida error')



cmdi_time = 0
try:
    with open(cmdi, 'r') as file:
        for line in file:
            if re.search("[a-zA-Z]", line):
                continue
            else:
                cmdi_time += float(line.strip())
except:
    print('cmdi error')


bof_time = 0
try:
    with open(bof, 'r') as file:
        for line in file:
            if re.search("[a-zA-Z]", line):
                continue
            else:
                bof_time += float(line.strip())
except:
    print('bof error')

env_time = 0
try:
    with open(env, 'r') as file:
        for line in file:
            if re.search("[a-zA-Z]", line):
                continue
            else:
                env_time += float(line.strip())
except:
    print('env error')

print('FOR: '+str(for_time))
print('ida: '+str(ida_time))
print('env: '+str(env_time))
print('CMDI: '+str(cmdi_time))
print('BOF: '+str(bof_time))
print('total: '+str(for_time+ida_time+cmdi_time+bof_time))