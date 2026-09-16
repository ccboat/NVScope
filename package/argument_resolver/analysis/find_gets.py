import subprocess
import os
import sys
import re
import time
import itertools
from pathlib import Path

from my_mango import MangoAnalysis

ENV_FUNCS = ['getenv', 'nvram_get', 'acosNvramConfig_get', 'acosNvramConfig_read', 'j_nvram_get', 'nvram_get_str',
             'bcm_nvram_get', 'envram_get', 'wlcsm_nvram_get', 'dni_nvram_get', 'PIT_nvram_get', 'nvram_safe_get',
             'httpGetEnv', 'GetValue']

EXEC_FUNCS = ['execve', 'execle']
SPRTF_FUNCS = ['sprintf', 'snprintf', 'slprintf', 'vsprintf', 'vsnprintf']

setters = ['setenv', 'script_setenv', 'nvram_set', 'acosNvramConfig_set', 'acosNvramConfig_write', 'j_nvram_set',
           'nvram_set_str', 'bcm_nvram_set', 'envram_set', 'wlcsm_nvram_set', 'dni_nvram_set', 'PIT_nvram_set',
           'nvram_safe_set', 'httpSetEnv', 'SetValue']

_border_binaries = ['httpd', 'uhttpd', 'http', 'lighttpd', 'acos_service', 'pppd', 'rc', 'cupsd', 'upnp', 'upnpd',
                    'udhcpd', 'udhcpc', 'udhcp', 'net-cgi', 'telnet', 'telnetd', 'utelnetd']


class TraceGetSet:

    def __init__(self, path, binary, outpath):
        global log

        self._path = path
        self._current_b = binary
        self.out_path = outpath

        # self._current_p = angr.Project(self._current_b, auto_load_libs=False)
        # self._current_cfg = self._current_p.analyses.CFG(data_references=True, cross_references=True)
        self._core_taint = None
        self._key_addr = None
        self._key_val = None

    def find_func_refs(self, func_name):
        func_addr = None
        symbols = self._current_p.loader.main_object.symbols
        for sym in symbols:
            if sym.name == func_name:
                if sym.is_import:
                    impts = self._current_p.loader.main_object.imports
                    func_addr = impts[func_name].rebased_addr
                else:
                    func_addr = sym.rebased_addr
                break

        refs = []

        if func_addr is None:
            print('There is no %s function in this binary!\n' % (func_name))
            return refs

        for ref in self._current_cfg.kb.xrefs.get_xrefs_by_dst(func_addr):
            if ref.type == 0:
                refs.append(ref.ins_addr)

        return refs

    def _check_key_val(self, current_path, *_, **__):
        state = current_path.active[0]
        no = self._current_cfg.get_any_node(state.addr)

        if no:
            if no.addr <= self._ref_addr <= no.addr + no.size:
                # now state in getenv callsite
                get_reg = state.regs.__getattr__(arg_reg_name(self._current_p, 0))
                if get_reg.concrete:
                    self._key_addr = get_reg.args[0]
                    self._key_val = state.memory.load(self._key_addr, 64)
                else:
                    self._key_val = None
                self._core_taint.stop_run()


    def get_arg(self, addr, idx):
        call_func = self._current_cfg.kb.functions.floor_func(addr)
        initial_state = self._p.factory.blank_state(remove_options={angr.options.LAZY_SOLVES})
        initial_state.ip = call_func.addr

        simgr = self._p.factory.simulation_manager(initial_state)
        simgr.explore(find=addr)

        if simgr.found:
            state = simgr.found[0]
            reg = state.regs.__getattr__(arg_reg_name(self._current_p, idx))
            if reg.concrete:
                return state.memory.load(reg.args[0], 64)
            else:
                self.trace_get_key(addr)


def grep_path(keyword, path):
    cmd = "grep -r '" + keyword + "' " + path + " | grep Binary"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, shell=True)
    out, e = p.communicate()
    return out


def fmt_handler(fmt_str, nn, kw_list):
    flags = r"[-+ #0]"
    width = r"\d+|\*"
    precision = r"\.(?:\d+|\*)"
    length = r"hh|h|l|ll|j|z|t|L"
    specifier = r"[diuoxXcsp\[]"
    pattern = rf"(%(?:{flags}{{0,5}})(?:{width})?(?:{precision})?(?:{length})?({specifier}))"
    pt = rf"(?:%(?:{flags}{{0,5}})(?:{width})?(?:{precision})?(?:{length})?({specifier}))"
    print(fmt_str)
    if nn:
        fmt_list = re.findall(pattern, fmt_str[2][0])
    else:
        fmt_list = re.findall(pattern, fmt_str[1][0])

    addn = 3 if nn else 2

    fmt_strs = {}
    for i in range(len(fmt_list)):
        if fmt_list[i][1] == 's':
            fmt_strs[i] = fmt_str[i + addn]
        else:
            fmt_strs[i] = [0]

    res_strs = []
    combs = list(itertools.product(*fmt_strs.values()))
    for cmb in combs:
        rs = fmt_str[addn - 1][0] % tuple(cmb)
        for kw in kw_list:
            if kw in rs:
                if rs.find(kw) == 0:
                    if kw + ' ' in rs or kw + '=' in rs:
                        res_strs.append((rs, kw))
    # print(res_strs)
    return res_strs


def trace_unknow(path, addr, setter):
    print(path)
    print(addr)
    print(setter)


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


def get_set_path(firm_path, res_path):
    set_bpaths = []
    with open(res_path + '/vendor.json', 'r') as f:
        vens = f.read()
    for root, dirs, files in os.walk(firm_path):
        for f in files:
            if '.so.0' in f or '.ko' in f:
                continue
            if os.path.join(root, f) not in vens:
                continue
            if os.path.getsize(os.path.join(root, f)) > 3 * 1024 * 1024:
                continue
            set_bpaths.append(os.path.join(root, f))

    set_bpaths = list(set(set_bpaths))
    print(set_bpaths)
    return set_bpaths


def save_results(out_dict, bres_path):
    sets = {}
    execs = {}
    sprtfs = {}
    for setter in out_dict:
        if setter in setters:
            if setter not in sets:
                sets[setter] = {}
            for addr in out_dict[setter]:
                key = out_dict[setter][addr][0]
                val = out_dict[setter][addr][1]
                if key['constant'] is not None:
                    for k in key['constant']:
                        if addr not in sets[setter]:
                            sets[setter][addr] = {}
                        if k not in sets[setter][addr]:
                            sets[setter][addr][k] = []
                        if len(val['constant']) > 0 and val['constant'] not in sets[setter][addr][k]:
                            sets[setter][addr][k].append(val['constant'])
                        if len(val['source']) > 0:
                            for func, v in val['source']:
                                if func != 'unknown':
                                    if v not in sets[setter][addr][k]:
                                        sets[setter][addr][k].extend(v)
                                else:
                                    if 'unknown' not in sets[setter][addr][k]:
                                        sets[setter][addr][k].append('unknown')

        if setter in EXEC_FUNCS:
            if setter not in execs:
                execs[setter] = {}
            for addr in out_dict[setter]:
                if addr not in execs[setter]:
                    execs[setter][addr] = []
                    envp = out_dict[setter][addr][len(out_dict[setter][addr]) - 1]
                    if envp not in execs[setter][addr]:
                        execs[setter][addr].append(envp)

        if setter in SPRTF_FUNCS:
            if setter not in sprtfs:
                sprtfs[setter] = {}
            for addr in out_dict[setter]:
                if addr not in sprtfs[setter]:
                    sprtfs[setter][addr] = {}
                if 'sn' in setter:
                    n = 2
                else:
                    n = 1
                for i in range(n, len(out_dict[setter][addr])):
                    vals = extract_value(out_dict[setter][addr][i])
                    sprtfs[setter][addr][i] = vals

    print(sets)
    print(execs)
    print(sprtfs)

    bout = open(bres_path + '/found_setters', 'w')
    bout.write('set funcs\n')
    bout.write(str(sets))
    bout.write('\nexec funcs\n')
    bout.write(str(execs))
    bout.write('\nsprintf funcs\n')
    bout.write(str(sprtfs))
    bout.close()


firm_path = sys.argv[1]
res_path = sys.argv[2]

print(firm_path)

set_bpaths = get_set_path(firm_path, res_path)

'''
outdir = res_path + 'setter_info/'
if not os.path.exists(outdir):
    os.mkdir(outdir)
    print(outdir)
'''
firm_name = Path(firm_path).parent.name
for binpath in set_bpaths:
    print(binpath)
    st = time.time()

    bin_respath = res_path + '/root'
    short_binpath = binpath.split(firm_name)[1]
    names_on_path = Path(short_binpath.strip('/')).parts[1:]
    print(short_binpath)
    print(names_on_path)
    
    for i in range(len(names_on_path)):
        bin_respath+='/'+names_on_path[i]
        if os.path.exists(bin_respath):
            continue
        else:
            os.mkdir(bin_respath)
            
    if os.path.exists(res_path + '/env_log'):
        with open(res_path + '/env_log', 'r') as fl:
            con = fl.read()
            if pa in con:
                print('already done')
                continue

    run = False
    for ss in setters+EXEC_FUNCS:
        if os.path.exists(bin_respath+'/ida/'+ss):
            run = True
            break
    if not os.path.exists(bin_respath + '/ida/'):
        run = True
    if not run:
        print('no setters')
        continue

    try:
        command = []
        command += ['python', 'package/argument_resolver/analysis/env_mango.py', binpath]
        command += ["--results", bin_respath]
        command += ["--keyword-dict", res_path + '/keywords.json']

        print(command)
        ret_code = subprocess.call(command)

        print('endend')

    except:
        print('analyze error')
        continue

    ed = time.time()
    with open(res_path + 'env_log', 'a+') as fl:
        fl.write(pa)
        fl.write('\n')
        fl.write(str(ed - st))
        fl.write('\n')
    print(str(ed - st))
    print(pa)
