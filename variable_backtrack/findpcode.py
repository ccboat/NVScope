#代码注释：通过伪代码角度，对sink点到src的所有函数路径的参数进行逆向回溯，剔除不可控的函数路径。target_var：父函数传给子函数的参数，var_list：子函数自定义的临时变量，initial_var：关键参数
from errno import EADDRINUSE
from aapc1 import assembly_check
import idautils
import ida_funcs
import idc
import ida_name
import networkx as nx
from collections import deque
import re
import os
import sys
import time


# TODO 1: modify level = [DEBUG|INFO]
#         modify debug = [True|False]
level = "INFO"
debug = False
# 输出到stdout，也可以输出到文件中

CMD_SINKS = ['system', '___system', 'bstar_system', 'doShell', 'CsteSystem', 'cgi_deal_popen', 'ExeCmd', 'ExecShell', 'exec_shell_popen', 'exec_shell_popen_str', 'popen', 'execl', 'execlp', 'execle', 'execv', 'execvp', 'execvpe', 'execve', 'tp_systemEx', 'exec_shell_async', 'exec_shell_sync', 'exec_shell_sync2', 'SLIBCSystem', 'SLIBCExecl', 'SLIBCExec', 'SLIBCExecv', 'SLIBCPopen', 'pegaSystem']
FMT_CMD_SINKS = ['execFormatCmd', 'doSystemCmd', 'twsystem', 'exec_cmd']
BOF_SINKS = ['strcpy']
SETTERS = ['setenv','script_setenv','nvram_set','acosNvramConfig_set','acosNvramConfig_write','j_nvram_set','nvram_set_str','bcm_nvram_set','envram_set','wlcsm_nvram_set','dni_nvram_set','PIT_nvram_set','nvram_safe_set','httpSetEnv','SetValue']
EXECS = ['execve', 'execle']

log_file = 'F:\\111-MyWork\\NVSCOPE\\实验\\数据集\\r1_for\\d-link\\DSR-150N\\root\\logloglog'
TIMEOUT = False


def find_insn_by_ea(cfunc, target_ea): #在CTree中查找给定地址的指令节点
    class MyVisitor(idaapi.ctree_visitor_t):
        def __init__(self, cfunc, target_ea):
            idaapi.ctree_visitor_t.__init__(self, idaapi.CV_FAST)
            self.cfunc = cfunc
            self.target_ea = target_ea
            self.target_node = None

        def visit_insn(self, insn):
            if insn.ea == self.target_ea:
                self.target_node = insn
                return 1  # Stop traversal
            return 0
    visitor = MyVisitor(cfunc, target_ea)
    visitor.apply_to(cfunc.body, None)
    return visitor.target_node


class MyCtree:
    def __init__(self, func_addr, sink_name, res_file):
        self.func_addr = func_addr
        print(hex(func_addr))
        self.func = ida_funcs.get_func(func_addr)
        if not self.func:
            idc.add_func(func_addr)
            self.func = ida_funcs.get_func(func_addr)
        start_addr = self.func.start_ea
        
        self.analyzed_vars = []
        self.effect_idx = []
        self.pre_process(start_addr)

        self.func = ida_funcs.get_func(start_addr)
        #print(hex(start_addr))
        print(self.func)

        self.sink_name = sink_name
        self.c_code, self.raw_code = self.get_psu(func_addr)
        print(len(self.c_code))
        self.res_file = res_file
        #print(res_file)
        self.arg_list, self.var_list = self.variable_extract(func_addr)
        print('init')

    def get_ctree(self, ea):
        f = idaapi.get_func(ea)
            
        if not f:
            idc.add_func(ea)
            f = idaapi.get_func(ea)
        try:
            cfunc = idaapi.decompile(f)
        except:
            cfunc = None
        
        if not cfunc:
            return None
        
        self.cfunc = cfunc
        self.func = f
        self.f_size = f.size()

        return cfunc


    def pre_process(self, addr):
        callees = set()
        print('pre')
        print(hex(addr))
        for inst_ea in idautils.FuncItems(addr):
            refs = idautils.CodeRefsFrom(inst_ea, False)
            for ref_ea in refs:
                if ida_funcs.get_func(ref_ea) and ida_funcs.get_func(ref_ea).start_ea != addr:
                    callees.add(ref_ea)
        
        idaapi.del_func(addr)
        for callee in callees:
            #print(hex(callee))
            callee_f = ida_funcs.get_func(callee)
            if callee_f.flags & ida_funcs.FUNC_THUNK:
                continue
            try:
                idaapi.decompile(callee)
            except:
                continue
        idaapi.add_func(addr)
        idaapi.auto_wait()


    def get_ccode(self, cfunc):
        code = []
        for item in cfunc.treeitems:
            ea = item.ea
            psu = idaapi.tag_remove(item.cexpr.print1(None))
            psu = idaapi.tag_remove(psu)
            op = item.op
            code.append((op, psu, ea))
        return code

    def get_type(self, op):
        if op == 65:
            return 'VAR'
        if op == 64:
            return 'STR'
        if op == 61:
            return 'INT'
        if op == 67:
            return 'RET'
        return None

    def solve_ccode(self, code):
        result = {}
        idx = 0
        while idx+1 < len(code):
            op, psu, ea = code[idx]
            if True:
                idx += 1
                n_op, n_psu, n_ea = code[idx]
                end = False
                print(code[idx])
                while not end:
                    if n_op == 57:
                        # function without return
                        print('func')
                        call_addr = n_ea
                        result[call_addr] = {}
                        result[call_addr]['RET'] = None
                        idx += 1
                        f_op, f_psu, f_ea = code[idx]
                        if f_op == 64 and f_ea == idaapi.BADADDR:
                            func_name = f_psu
                            result[call_addr]['TYPE'] = 'FUNC'
                            result[call_addr]['FUNC_NAME'] = func_name
                            result[call_addr]['FUNC_ARGS'] = []
                        else:
                            result[call_addr]['TYPE'] = 'ERROR'
                            end = True
                            continue
                        idx += 1
                        while idx < len(code) and code[idx][0] not in [28, 49, 71, 72, 73, 80, 81] and code[idx][0]!=57:
                            v_op, v_psu, v_ea = code[idx]
                            if v_op in [64, 61, 65, 67] or v_ea != idaapi.BADADDR:
                                var = v_psu
                                var_type = self.get_type(v_op)
                                if var_type:
                                    result[call_addr]['FUNC_ARGS'].append((var, var_type))
                            idx +=1
                        if idx >= len(code):
                            end = True
                            continue
                        if code[idx][0] in [28, 49, 71, 72, 73, 80, 81]:
                            end = True
                            continue
                        if code[idx][0] == 57:
                            end = False
                            n_op, n_psu, n_ea = code[idx]
                        
                    elif n_op == 2:
                        print('equ')
                        idxx = idx + 1
                        while idxx < len(code) and code[idxx][0] not in [28, 49, 71, 72, 73, 80, 81] and code[idxx][0]!=57:
                            idxx += 1

                        print(idxx)
                        print(len(code))

                        if idxx == len(code):
                            # a = b
                            result[n_ea] = {}
                            result[n_ea]['TYPE'] = 'EQUATION'
                            result[n_ea]['EQU_ARGS'] = []
                            idx += 1
                            v_op, v_psu, v_ea = code[idx]
                            while idx < len(code) and v_op != 57 and v_op not in [28, 49, 71, 72, 73, 80, 81]:
                                print(v_op)
                                v_op, v_psu, v_ea = code[idx]
                                var_type = self.get_type(v_op)
                                if var_type:
                                    print((v_psu, var_type))
                                    result[n_ea]['EQU_ARGS'].append((v_psu, var_type))
                                idx += 1
                                print(idx)
                                print(idx<len(code))
                                if idx<len(code):
                                    v_op, v_psu, v_ea = code[idx]
                                else:
                                    print('break')
                                    break
                            print(result)
                            end = True                  

                        elif code[idxx][0] == 57:
                            # function with return
                            r_op, r_psu, r_ea = code[idx+1]
                            print('ret')
                            print(r_psu)
                            call_addr = code[idxx][2]
                            idx = idxx + 1
                            f_op, f_psu, f_ea = code[idx]
                            result[call_addr] = {}
                            result[call_addr]['RET'] = (r_psu, self.get_type(r_op))
                            if f_op == 64 and f_ea == idaapi.BADADDR:
                                func_name = f_psu
                                result[call_addr]['TYPE'] = 'FUNC'
                                result[call_addr]['FUNC_NAME'] = func_name
                                result[call_addr]['FUNC_ARGS'] = []
                            else:
                                result[call_addr]['TYPE'] = 'ERROR'
                                end = True
                                continue
                            idx += 1
                            while idx < len(code) and code[idx][0] not in [28, 49, 71, 72, 73, 80, 81] and code[idx][0]!=57:
                                v_op, v_psu, v_ea = code[idx]
                                if v_op in [64, 61, 65, 67] or v_ea != idaapi.BADADDR:
                                    var = v_psu
                                    var_type = self.get_type(v_op)
                                    if var_type:
                                        result[call_addr]['FUNC_ARGS'].append((var, var_type))
                                idx +=1
                            if idx >= len(code):
                                end = True
                                continue
                            if code[idx][0] in [28, 49, 71, 72, 73, 80, 81]:
                                end = True
                                continue
                            if code[idx][0] == 57:
                                end = False
                                n_op, n_psu, n_ea = code[idx]
                        
                        elif code[idxx][0] in [28, 49, 71, 72, 73, 80, 81]:
                            # a = b
                            result[n_ea] = {}
                            result[n_ea]['TYPE'] = 'EQUATION'
                            result[n_ea]['EQU_ARGS'] = []
                            idx += 1
                            v_op, v_psu, v_ea = code[idx]
                            while idx < len(code) and v_op != 57 and v_op not in [28, 49, 71, 72, 73, 80, 81]:
                                print(v_op)
                                v_op, v_psu, v_ea = code[idx]
                                var_type = self.get_type(v_op)
                                if var_type:
                                    result[n_ea]['EQU_ARGS'].append((v_psu, var_type))
                                idx += 1
                                v_op, v_psu, v_ea = code[idx]
                            
                            end = True
                            if code[idx][0] == 57:
                                idx -=1
                            
                        
                        else:
                            print('?')
                            pass
                        
                    else:
                        end = True
        print(result)
        return result

    def get_psu(self, ea):
        print('psu')
        func = ida_funcs.get_func(ea)
        #print(ea)
        if not func:
            idc.add_func(ea)
            func = ida_funcs.get_func(ea)
        print(func)

        #assembly_check(ea)

        cfunc = idaapi.decompile(func)
        print(cfunc)
        c_code = self.get_ccode(cfunc)
        print(len(c_code))
        #print(c_code)
        res = self.solve_ccode(c_code)
        print(len(res))
        #print(res)
        print('psu end')

        return res, c_code



    def find_douhao(self, s):
        in_quotes = False
        semicolon_positions = []

        for i, char in enumerate(s):
            if char == '"' and (i == 0 or s[i-1] != '\\'):  # 检查引号是否被转义
                in_quotes = not in_quotes
            elif char == ',' and not in_quotes:
                semicolon_positions.append(i)

        return semicolon_positions


    def decompile_addr_code(self, code_addr): #对指定指令地址进行反编译，生成伪代码
        try:
            cfunc = self.get_ctree(code_addr)
        except:
            idc.add_func(code_addr)
            cfunc = self.get_ctree(code_addr)
        if not cfunc:
            return
        self.c_code = self.get_psu(code_addr)
    
    
    def variable_extract(self, func_addr):  #target_list和var_list提取
        func = ida_funcs.get_func(func_addr)
        if not func:
            idc.add_func(func_addr)
            func = ida_funcs.get_func(func_addr)
        if func is None:
            return None
        else:
            try:
                cfunc=idaapi.decompile(func_addr)
            except:
                cfunc = None
            if cfunc is None:
                return None
            else:
                target_var=[]
                var_list=[]
                for i, arg in enumerate(cfunc.arguments):
                    target_var.append(arg.name)
                for lvar in cfunc.lvars:
                    if lvar.name:
                        var_list.append(lvar.name)
            var_list=[item for item in var_list if item not in target_var]
            return target_var, var_list


    def find_func_xref(self, func_name):
        xrefs = []
        ad = self.func.start_ea
        #print(ad)
        #print(func_name)
        while ad <= self.func.end_ea:
            try:
                if idaapi.is_call_insn(ad):
                    callee_ad, name = self.get_callee(ad)   # callee_ad
                    #print(hex(ad))
                    #print(name)
                    if name == func_name:
                        xrefs.append(ad)
            except:
                ad += 4
                continue
            ad += 4
        #print(xrefs)
        print('xref end')
        return xrefs


    def get_args(self, ccode, func_addr, func_name):
        print('get args')
        f_code = ccode[func_addr]
        #print(f_code)
        if f_code['FUNC_NAME'] == func_name:
            args = f_code['FUNC_ARGS']
        else:
            args = []
        #print(args)
        for i in range(0, len(args)):
            #print(args[i])
            #print(args[i][0])
            if 'dword' in args[i][0]:
                args[i] = (args[i][0],'VAR')
        return args


    def is_constant(self, str):
        if str[0] == '\"' and str[-1] == '\"':
            return True
        if str[0] == '\'' and str[-1] == '\'':
            return True
        return False


    def handle_func(self, func_name):
        pass

    
    def match_var(self, code, var_list):
        vars = []
        for i in var_list:
            if i in code:
                pattern = r'(?:^|\s|&|,|;|\(|\)){}($|\s|&|,|;|\(|\))'.format(re.escape(i))
                match = re.search(pattern, code)
                if match:
                    #print('match')
                    vars.append(i)
        return vars

    def get_order_args(self, ccode, addr, name, var_list):
        #print(addr)
        tar_code = ''
        for op, code, ad in ccode:
            if op == 57 and ad == addr:
                #print('111')
                tar_code = code
                #print(tar_code)
                break
        print('get_order_args')
        #print(name)
        try:
            arg_lis = tar_code.split(name+'(')[1][:-1]
        except:
            arg_lis = ''
        #print(arg_lis)
        if not arg_lis:
            res = []
            print('no args')
            return res

        semi_locs = self.find_douhao(arg_lis)
        #print(semi_locs)
        if len(semi_locs) > 0:
            st = 0
            ed = semi_locs[0]
            args = []
            for i in range(len(semi_locs)):
                arg = arg_lis[st: ed].strip()
                #print(arg)
                m_vars = self.match_var(arg, var_list)
                if len(m_vars) > 0:
                    args.extend(m_vars)
                else:
                    args.append(arg)
                try:
                    st = semi_locs[i] + 1
                    ed = semi_locs[i+1]
                except:
                    break
            arg = arg_lis[semi_locs[-1]+1:]
            #print(arg)
            m_vars = self.match_var(arg, var_list)
            if len(m_vars) > 0:
                args.extend(m_vars)
            else:
                args.append(arg)
        else:
            args = []
            m_vars = self.match_var(arg_lis, var_list)
            if len(m_vars) > 0:
                args.extend(m_vars)
            else:
                args.append(arg_lis)
        print(args)
        return args
    
    #pattern = r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^()]*)\)'

    def get_callee(self, addr):
        print('ins addr '+hex(addr))
        if idaapi.is_call_insn(addr):
            insn = idautils.DecodeInstruction(addr)
        else:
            return None, None
        try:
            op = insn.Op1
            if op.type == idaapi.o_reg:
                cur_ea = addr
                reg = idc.print_operand(addr, 1)
                while cur_ea > ida_funcs.get_func(addr).start_ea:
                    cur_ea = idc.prev_head(cur_ea)
                    if idc.print_operand(cur_ea, 0) == reg:
                        #print(hex(cur_ea))
                        if idc.print_operand(cur_ea, 1).startswith('$'):
                            reg = idc.print_operand(cur_ea, 1)
                            #print(reg)
                            continue
                        callee_addr = idc.get_operand_value(cur_ea, 1)
                        name = ida_funcs.get_func_name(callee_addr)
                        break
                return callee_addr, name
            elif op.type == idaapi.o_near or op.type == idaapi.o_far:
                callee_addr = op.addr
                name = ida_funcs.get_func_name(callee_addr)
                return callee_addr, name
            else:
                #print(op.type)
                return None, None 
        except:
            return None, None
        return None, None 
        

    def trace_callee(self, addr, idx):
        global TIMEOUT, log_file

        print('callee')
        print(hex(addr))
        res = []

        v = ('a'+ str(idx+1), 'VAR')
        trace_addrs = [(addr,v)]

        start_time0 = time.time()
        analyzed_addrs = []
        with open(log_file,'a+') as f_log:
            f_log.write('trace callee\n')

        while trace_addrs:
            #with open(log_file,'a+') as f_log:
            #    f_log.write('trace callee addrs\n')
            #    f_log.write(str(time.time() - start_time0)+'\n')
            #print(time.time())
            if (time.time() - start_time0) > 300:
                print(f"TIME OUT for trace_callee: {addr}&{idx}\n")
                TIMEOUT = True
                return []
            t_ad, tv = trace_addrs.pop(0)
            trace_vars = [tv]
            analyzed_addrs.append(t_ad)
            print('extract var')
            print(t_ad)
            arg_list, var_list = self.variable_extract(t_ad)
            c_code, raw_code = self.get_psu(t_ad)
            

            analyzed_vars = []
            start_time1 = time.time()

            while trace_vars:
                #with open(log_file,'a+') as f_log:
                #    f_log.write('trace vars\n')
                #    f_log.write(str(time.time()-start_time1)+'\n')
                #print(time.time())
                if (time.time() - start_time1) > 300:
                    print(f"TIME OUT for trace_callee: {addr}&{idx}\n")
                    TIMEOUT = True
                    break
                key = trace_vars.pop(0)
                analyzed_vars.append(key)
                #print(key)
                #print(c_code)
                for ad in c_code:
                    code = c_code[ad]
                    #print(code)
                    if code['TYPE'] == 'FUNC':
                        args = code['FUNC_ARGS'].copy()
                        ret = code['RET']
                        if ret:
                            args.append(ret)
                        #print(args)
                        if key in args:
                            print('in func')
                            #print(code)
                            if ad not in res:
                                res.append(ad)
                            for arg in args:
                                if arg not in analyzed_vars and arg not in trace_vars and arg[1] == 'VAR':
                                    trace_vars.append(arg)
                                    #print('append '+str(arg))

                            if idaapi.is_call_insn(ad):
                                called_addr, name = self.get_callee(ad)
                                vars = self.get_order_args(raw_code, ad, name, arg_list+var_list)
                                #print(called_addr)
                                #print(vars)
                                try:
                                    idx = vars.index(key[0])
                                except:
                                    continue
                                if called_addr and called_addr not in analyzed_addrs and (called_addr, ('a'+str(idx+1), 'VAR')) not in trace_addrs:
                                    func_tmp = ida_funcs.get_func(called_addr)
                                    try:
                                        cfunc_tmp = idaapi.decompile(func_tmp)
                                    except:
                                        print('not do callee')
                                        continue
                                    trace_addrs.append((called_addr, ('a'+str(idx+1), 'VAR')))

                    if code['TYPE'] == 'EQUATION':
                        args = code['EQU_ARGS'].copy()
                        #print(args)
                        if key in args:
                            #print('in')
                            #print(code)
                            #if ad not in res:
                            #    res.append(ad)
                            for arg in args:
                                if arg not in analyzed_vars and arg not in trace_vars and arg[1] == 'VAR':
                                    trace_vars.append(arg)
                                    #print('append '+str(arg))
        print('callee end')
        print(res)
        return res


    def trace(self, addr, key):
        global TIMEOUT, log_file

        trace_addrs = []
        trace_addrs.append(addr)

        trace_vars = []
        trace_vars.append(key)

        analyzed_vars = []
        analyzed_callee = []

        start_time = time.time()
        print(f'START TIME: {start_time}')
        print(trace_vars)
        with open(log_file,'a+') as f_log:
            f_log.write('trace\n')

        print('trace')

        while trace_vars:
            print(time.time())
            print(trace_vars)
            
            key = trace_vars.pop(0)
            print(key)
            
            try:
                if TIMEOUT:
                    print('timeout\n')
                    return []
                with open(log_file,'a+') as f_log:
                    f_log.write('trace trace var\n')
                    f_log.write(str(time.time() - start_time)+'\n')
                if time.time() - start_time > 300:
                    print(f"TIME OUT for {addr}&{key}\n")
                    TIMEOUT = True
                    with open(log_file,'a+') as f_log:
                        f_log.write('trace trace var TIMEOUT\n')
                    return []
            except:
                print('ERROR')
            
            analyzed_vars.append(key)
            #print(key)

            for ad in self.c_code:
                if TIMEOUT:
                    break
                if ad >= addr:
                    continue
                code = self.c_code[ad]
                #print(code)
                
                if code['TYPE'] == 'FUNC':
                    args = code['FUNC_ARGS'].copy()

                    if code['RET'] is not None:
                        args.append(code['RET'])
                    #print(args)

                    if key in args:
                        print('in')
                        #print(hex(ad))
                        if ad not in trace_addrs:
                            trace_addrs.append(ad)
                        #print(trace_addrs)
                        for arg in args:
                            #print(arg)
                            if arg not in analyzed_vars and arg not in trace_vars and arg[1] == 'VAR':
                                trace_vars.append(arg)
                                #print('append '+str(arg))

                        if idaapi.is_call_insn(ad):
                            called_addr, name = self.get_callee(ad)
                            #print(called_addr)
                            vars = self.get_order_args(self.raw_code, ad, name, self.arg_list+self.var_list)
                            #print(vars)
                            #print(key[0])
                            try:
                                idx = vars.index(key[0])
                            except:
                                continue
                            if called_addr:
                                #print(called_addr)
                                #print(analyzed_callee)
                                if (called_addr, idx, key[0]) not in analyzed_callee:
                                    func_tmp = ida_funcs.get_func(called_addr)
                                    try:
                                        cfunc_tmp = idaapi.decompile(func_tmp)
                                    except:
                                        #print('not do callee')
                                        continue

                                    #print('do callee')
                                    res = self.trace_callee(called_addr, idx)
                                    analyzed_callee.append((called_addr, idx, key[0]))
                                    if res:
                                        trace_addrs.extend(res)
                                    
                                #print(trace_addrs)

                if code['TYPE'] == 'EQUATION':
                    args = code['EQU_ARGS'].copy()
                    #print(args)
                    if key in args:
                        #print('in equ')
                        if ad not in trace_addrs:
                            trace_addrs.append(ad)
                        #print(trace_addrs)
                        for arg in args:
                            #print(arg)
                            if arg not in analyzed_vars and arg not in trace_vars and arg[1] == 'VAR':
                                trace_vars.append(arg)
                                #print('append '+str(arg))
        print('trace end')
        #print(trace_vars)
        #print(trace_addrs)
        return trace_addrs


    def handle_system(self, addr, args):
        arg_name, arg_type = args[0]
        if arg_type == 'VAR':
            return self.trace(addr, args[0])
        else:
            return 'constant'

    def handle_fmt_system(self, addr, args):
        result = []
        for arg in args:
            if arg[1] == 'VAR':
                res = self.trace(addr, arg)
                result = result + res
        if len(result) == 0:
            return 'constant'
        return result

    def handle_strcpy(self, addr, args):
        src = args[-1]
        
        print('handle strcpy')
        print(src)
        
        for i in range(0, len(args)-1):
            if args[i][1] == 'VAR':
                return self.trace(addr, src)
        return 'constant'

    def handle_setter(self, addr, args):
        print('handle setter')
        res = []
        print(args)
        key_name, key_type = args[0]
        if key_type == 'VAR':
            res += self.trace(addr, args[0])
        print('\nhandle setter 0')
        print(res)
        val_name, val_type = args[1]
        if val_type == 'VAR':
            res += self.trace(addr, args[1])
        print('\nhandle setter 1')
        print(res)
        if len(res) == 0:
            return 'constant'
        return res

    def handle_exec(self, addr, args):
        print('handle exec')
        arg_name, arg_type = args[-1]
        if arg_type == 'VAR':
            return self.trace(addr, args[-1])
        else:
            return 'constant'

    def handle_comm_func(self, addr, args, idxs):
        print('handle comm')
        print(hex(addr))
        if len(args) == 0:
            return 'no dependency'

        constant = True
        effects = []
        for idx in idxs:
            arg = args[idx]
            if arg[1] == 'VAR':
                constant = False
                print('trace arg'+str(idx))
                print(arg)
                effects += self.trace(addr, arg)

        if constant:
            return 'constant'
        elif len(effects) == 0:
            return 'no dependency'
        else:
            return effects



    def analyze(self):
        #self.decompile_addr_code(self.func_addr)
        #print(self.c_code)
        sink_xrefs = self.find_func_xref(self.sink_name)        # find all sink's call sites in caller
        print('sink xrefs')
        print(sink_xrefs)
        with open(log_file,'a+') as f_log:
            f_log.write('sink xrefs\n')
            f_log.write(str(sink_xrefs)+'\n')

        effect_addrs = []

        if self.sink_name in CMD_SINKS:
            constant = True
            for sink in sink_xrefs:
                try:
                    if TIMEOUT:
                        effect_addrs = []
                        break
                    print('\nanalyze sink')
                    with open(log_file,'a+') as f_log:
                        f_log.write('analyze sink\n')
                        f_log.write(hex(sink)+'\n')
                    print(self.raw_code)
                    sink_ord_args = self.get_order_args(self.raw_code, sink, self.sink_name, self.arg_list+self.var_list)
                    sink_args = self.get_args(self.c_code, sink, self.sink_name)
                    print('args')
                    args = []
                    for a in sink_ord_args:
                        for j in sink_args:
                            if a == j[0]:
                                args.append(j)
                                break
                    print(hex(sink))
                    print(args)
                    res = self.handle_system(sink, sink_args)
                except:
                    res = [sink]
               
                if res == 'constant':
                    print('NOT VUL')
                    effect_addrs.append(sink)
                elif res == None:
                    print('ERROR')
                else:
                    if isinstance(res, list):
                        constant = False
                        #print(res)
                        effect_addrs += res
            
            with open(self.res_file, 'w') as f:
                print(self.res_file)
                f.write(hex(self.func_addr))
                f.write('\n')
                effect_addrs = list(set(effect_addrs))
                for ad in effect_addrs:
                    try:
                        if self.c_code[ad]['TYPE'] == 'FUNC':
                            f.write(hex(ad))
                            f.write('\n')
                    except:
                        f.write(hex(ad))
                        f.write('\n')
            return constant
        
        if self.sink_name in FMT_CMD_SINKS:
            constant = True
            for sink in sink_xrefs:
                try:
                    if TIMEOUT:
                        effect_addrs = []
                        break
                    print('\nanalyze sink')
                    with open(log_file,'a+') as f_log:
                        f_log.write('analyze sink\n')
                        f_log.write(hex(sink)+'\n')
                    print(self.raw_code)
                    sink_ord_args = self.get_order_args(self.raw_code, sink, self.sink_name, self.arg_list+self.var_list)
                    sink_args = self.get_args(self.c_code, sink, self.sink_name)
                    print('args')
                    args = []
                    for a in sink_ord_args:
                        for j in sink_args:
                            if a == j[0]:
                                args.append(j)
                                break
                    print(hex(sink))
                    print(args)
                    res = self.handle_fmt_system(sink, sink_args)
                except:
                    res = [sink]
               
                if res == 'constant':
                    print('NOT VUL')
                    effect_addrs.append(sink)
                elif res == None:
                    print('ERROR')
                else:
                    if isinstance(res, list):
                        constant = False
                        #print(res)
                        effect_addrs += res
            
            with open(self.res_file, 'w') as f:
                print(self.res_file)
                f.write(hex(self.func_addr))
                f.write('\n')
                effect_addrs = list(set(effect_addrs))
                for ad in effect_addrs:
                    try:
                        if self.c_code[ad]['TYPE'] == 'FUNC':
                            f.write(hex(ad))
                            f.write('\n')
                    except:
                        f.write(hex(ad))
                        f.write('\n')
            return constant

        elif self.sink_name in BOF_SINKS:
            constant = True
            print(sink_xrefs)
            for sink in sink_xrefs:
                try:
                    if TIMEOUT:
                        effect_addrs = []
                        break
                    print('\nanalyze sink')
                    with open(log_file,'a+') as f_log:
                        f_log.write('analyze sink\n')
                        f_log.write(hex(sink)+'\n')
                    print(len(self.raw_code))
                    print(hex(sink))
                    sink_ord_args = self.get_order_args(self.raw_code, sink, self.sink_name, self.arg_list+self.var_list)
                    sink_args = self.get_args(self.c_code, sink, self.sink_name)
                    print('sink args')
                    print(sink_args)
                    print('ord args')
                    print(sink_ord_args)
                    args = []
                    for a in sink_ord_args:
                        for j in sink_args:
                            if a == j[0] or j[0] in a:
                                args.append(j)
                                break
                    print(hex(sink))
                    print(args)
                    res = self.handle_strcpy(sink, args)
                except:
                    res = [sink]

                if res == 'constant':
                    print('bof NOT VUL')
                    effect_addrs.append(sink)
                elif res == None:
                    print('ERROR')
                else:
                    if isinstance(res, list):
                        constant = False
                        print(res)
                        effect_addrs += res
            for a in effect_addrs:
                print(hex(a))
                
            with open(self.res_file, 'w') as f:
                print(self.res_file)
                f.write(hex(self.func_addr))
                f.write('\n')
                effect_addrs = list(set(effect_addrs))
                for ad in effect_addrs:
                    try:
                        if self.c_code[ad]['TYPE'] == 'FUNC':
                            f.write(hex(ad))
                            f.write('\n')
                    except:
                        f.write(hex(ad))
                        f.write('\n')
            return constant
        #elif self.sink_name in SETTERS or self.sink_name in EXECS:
        #    continue
        elif self.sink_name in SETTERS:
            constant = True
            for sink in sink_xrefs:
                try:
                    if TIMEOUT:
                        effect_addrs = []
                        break
                    print('\nanalyze sink')
                    with open(log_file,'a+') as f_log:
                        f_log.write('analyze sink\n')
                        f_log.write(hex(sink)+'\n')
                    print(self.raw_code)
                    sink_ord_args = self.get_order_args(self.raw_code, sink, self.sink_name, self.arg_list+self.var_list)
                    sink_args = self.get_args(self.c_code, sink, self.sink_name)
                    print('args')
                    args = []
                    for a in sink_ord_args:
                        for j in sink_args:
                            if a == j[0]:
                                args.append(j)
                                break
                    print(hex(sink))
                    print(args)
                    res = self.handle_setter(sink, args)
                except:
                    res = [sink]
               
                if res == 'constant':
                    print('NOT VUL')
                    effect_addrs.append(sink)
                elif res == None:
                    print('ERROR')
                else:
                    if isinstance(res, list):
                        constant = False
                        #print(res)
                        effect_addrs += res
            
            with open(self.res_file, 'w') as f:
                print(self.res_file)
                f.write(hex(self.func_addr))
                f.write('\n')
                effect_addrs = list(set(effect_addrs))
                for ad in effect_addrs:
                    try:
                        if self.c_code[ad]['TYPE'] == 'FUNC':
                            f.write(hex(ad))
                            f.write('\n')
                    except:
                        f.write(hex(ad))
                        f.write('\n')
            return constant
        
        elif self.sink_name in EXECS:
            constant = True
            for sink in sink_xrefs:
                try:
                    if TIMEOUT:
                        effect_addrs = []
                        break
                    print('\nanalyze sink')
                    with open(log_file,'a+') as f_log:
                        f_log.write('analyze sink\n')
                        f_log.write(hex(sink)+'\n')
                    print(self.raw_code)
                    sink_ord_args = self.get_order_args(self.raw_code, sink, self.sink_name, self.arg_list+self.var_list)
                    sink_args = self.get_args(self.c_code, sink, self.sink_name)
                    print('args')
                    args = []
                    for a in sink_ord_args:
                        for j in sink_args:
                            if a == j[0]:
                                args.append(j)
                                break
                    print(hex(sink))
                    print(args)
                    res = self.handle_exec(sink, args)
                except:
                    res = [sink]
               
                if res == 'constant':
                    print('NOT VUL')
                    effect_addrs.append(sink)
                elif res == None:
                    print('ERROR')
                else:
                    if isinstance(res, list):
                        constant = False
                        #print(res)
                        effect_addrs += res
            
            with open(self.res_file, 'w') as f:
                print(self.res_file)
                f.write(hex(self.func_addr))
                f.write('\n')
                effect_addrs = list(set(effect_addrs))
                for ad in effect_addrs:
                    try:
                        if self.c_code[ad]['TYPE'] == 'FUNC':
                            f.write(hex(ad))
                            f.write('\n')
                    except:
                        f.write(hex(ad))
                        f.write('\n')
            return constant
        else:
            constant = True
            for sink in sink_xrefs:
                try:
                    if TIMEOUT:
                        effect_addrs = []
                        break
                    print('\nanalyze sink')
                    with open(log_file,'a+') as f_log:
                        f_log.write('analyze sink\n')
                        f_log.write(hex(sink)+'\n')
                    print(self.raw_code)
                    sink_ord_args = self.get_order_args(self.raw_code, sink, self.sink_name, self.arg_list+self.var_list)
                    sink_args = self.get_args(self.c_code, sink, self.sink_name)
                    print('args')
                    args = []
                    for a in sink_ord_args:
                        for j in sink_args:
                            if a == j[0]:
                                args.append(j)
                                break
                    print(hex(sink))
                    print(args)
                    
                    print(self.effect_idx)
                    if len(self.effect_idx) == 0:
                        res = 'no dependency'
                    else:
                        res = self.handle_comm_func(sink, args, self.effect_idx)
                except:
                    res = [sink]
                if res == 'no dependency':
                    print('NO DEP')
                    effect_addrs.append(sink)
                elif res == 'constant':
                    print('CONSTANT DEP')
                    effect_addrs.append(sink)
                else:
                    if isinstance(res, list):
                        constant = False
                        print(res)
                        effect_addrs += res

            with open(self.res_file, 'w') as f:
                print(self.res_file)
                print(self.res_file)
                f.write(hex(self.func_addr))
                f.write('\n')
                effect_addrs = list(set(effect_addrs))
                for ad in effect_addrs:
                    try:
                        if self.c_code[ad]['TYPE'] == 'FUNC':
                            f.write(hex(ad))
                            f.write('\n')
                    except:
                        f.write(hex(ad))
                        f.write('\n')
            return constant




if __name__ == '__main__':
    start = time.time( )
    
    #args = idc.ARGV
    
    trace_path='F:\\111-MyWork\\NVSCOPE\\实验\\数据集\\r1_for\\d-link\\DSR-150N\\root\\bin\\dhcpd\\ida\\strcpy'
    res_path='F:\\111-MyWork\\NVSCOPE\\实验\\数据集\\r1_for\\d-link\\DSR-150N\\root\\bin\\dhcpd\\ida_result\\strcpy'

    #trace_path = args[1]
    #res_path = args[2]

    sink = trace_path.split('\\')[-1]
    analyzed = []
    effect_idx = []

    if True:
        with open(trace_path, 'r') as f:
            cont = f.readlines()

        for index, item in enumerate(cont):
            TIMEOUT = False
            print(f"\n{index}/{len(cont)}")
            ii = item.strip().split(' ')
            print(ii)
            with open(log_file,'a+') as f_log:
                f_log.write(item)
            if len(ii) == 1:
                caller = ii[0].split(',')[0]
                callee = ii[0].split(',')[1]
                sink_name = ida_name.get_name(int(callee, 16))
                if not sink_name:
                    sink_name = sink
                f_name = caller+'_'+callee

                print(res_path + '\\' + f_name)
                if os.path.exists(res_path + '\\' + f_name):
                    print('already done')
                    continue

                mytree = MyCtree(int(caller, 16), sink_name, res_path + '\\' + f_name)
                
                r = mytree.analyze()

            elif len(ii) > 1:
                flag = 1
                for j in range(len(ii)):
                    caller = ii[j].split(',')[0]
                    callee = ii[j].split(',')[1]
                    f_name = caller+'_'+callee
                    resp = res_path + '\\' + f_name
                    if os.path.exists(resp):
                        flag = 1
                    else:
                        flag = 0
                if flag == 1:
                    print('already done')
                    continue

                for j in range(len(ii)):
                    caller = ii[j].split(',')[0]
                    callee = ii[j].split(',')[1]
                    sink_name = ida_name.get_name(int(callee, 16))
                    if not sink_name and j == 0:
                        sink_name = sink
                    f_name = caller+'_'+callee

                    print(res_path + '\\' + f_name)

                    mytree = MyCtree(int(caller, 16), sink_name, res_path + '\\' + f_name)
                    mytree.effect_idx = effect_idx

                    is_constant = mytree.analyze()
                    print(ii[j])
                    print(is_constant)
                    if is_constant:
                        break

                    analyzed = mytree.analyzed_vars
                    effect_idx = []
                    if len(analyzed)>0:
                        for i in analyzed:
                            if i[1] == 'VAR' and i[0] in mytree.arg_list:
                                effect_idx.append(mytree.arg_list.index(i[0]))
                        print(effect_idx)
            else:
                continue

        end = time.time()

        t = end - start
        print(t)

    #idc.qexit(0)
