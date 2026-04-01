import os
import subprocess
import time
import re
import sys

ida_path = 'idat'
script_path = 'findpcode.py'
firm_path = sys.argv[1]
trace_path = sys.argv[2]

try:
    with open(trace_path+'/ida_log', 'r') as idalog:
        donebins = idalog.read()
except:
    donebins = []

for root, dirs, files in os.walk(trace_path):
    for file in files:
        file_path = os.path.join(root, file)

        if 'ida_result' not in file_path and 'ida_log' not in file_path and 'ida' in file_path:
            res_f =file_path.replace('ida', 'ida_result')
        else:
            continue

        #if os.path.exists(res_f):
        #    continue
        print(file_path)
        short_binpath = file_path.split('/ida')[0].split('root/')[1]
        bin_path = firm_path + '/' + short_binpath
        print(bin_path)

        if file_path.split('root')[1] in donebins:
            continue
        
        os.makedirs(res_f, exist_ok=True)
        print(res_f)

        sink = file_path.split('/')[-1]
        print(sink)

        cmd = f'"{ida_path}" -A -S"findpcode.py {file_path} {res_f}" "{bin_path}"'
        print(cmd)

        st = time.time()
        try:
            subprocess.run(cmd, shell=True, capture_output=True, timeout=1200)
        except subprocess.TimeoutExpired as e:
            print(f"错误：命令执行超时！限制为 {e.timeout} 秒。")
            # 如果设置了 capture_output，你甚至可以获取超时前产生的“部分输出”
            if e.stdout:
                print("超时前的部分输出:", e.stdout)
            if e.stderr:
                print("超时前的错误输出:", e.stderr)
        except Exception as e:
            print(f"发生了其他错误: {e}")

        ed = time.time()

        with open(trace_path + '/ida_log','a+') as ff:
            ff.write(file_path.split('root')[1])
            ff.write('\n')
            ff.write(str(ed-st)+'\n')
