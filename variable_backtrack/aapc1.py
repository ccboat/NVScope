import ida_idaapi
import ida_funcs
import ida_bytes
import ida_ua
import ida_idp
import ida_hexrays
import ida_typeinf
import ida_name
import idautils
import ida_nalt
import idc


class ParamFixer:
    def __init__(self):
        # 定义标准 MIPS 寄存器，这些通常不用作"隐藏"参数，或者是系统保留的
        # 如果是 ARM，这里改为 R0-R3, SP, LR, PC 等
        self.standard_regs = {
            '$a0', '$a1', '$a2', '$a3',  # 标准参数
            '$zero', '$at',             # 零寄存器，汇编器保留
            '$k0', '$k1',               # 内核保留
            '$gp', '$sp', '$fp', '$ra'  # 指针和返回地址
        }
        
        # 扫描函数头部的深度 (指令数)
        self.SCAN_DEPTH = 30
        # 回溯调用者的深度 (指令数)
        self.BACKTRACK_DEPTH = 10
        # 活跃性阈值 (多少比例的 Caller 赋值了该寄存器才算数)
        self.CONFIDENCE_THRESHOLD = 0.8

    def _is_reg_op(self, op):
        """判断操作数是否为寄存器"""
        return op.type == ida_ua.o_reg

    def _get_reg_name(self, op):
        """获取规范化的寄存器名称"""
        return ida_idp.get_reg_name(op.reg, 4) # 4 bytes width usually

    def get_ubd_candidates(self, func_ea):
        """
        步骤 1: 基于先读后写 (Use-Before-Define) 识别潜在参数
        返回: 潜在的参数寄存器集合 (如 {'$t0', '$v0'})
        """
        func = ida_funcs.get_func(func_ea)
        if not func:
            return set()

        defined_regs = set()
        candidates = set()

        # 遍历函数的前 N 条指令
        count = 0
        for ea in idautils.Heads(func.start_ea, func.end_ea):
            if count > self.SCAN_DEPTH:
                break
            count += 1

            insn = idautils.DecodeInstruction(ea)
            if not insn: continue

            # 获取指令特征 (Feature)
            feature = insn.get_canon_feature()

            # 检查每个操作数
            # IDA 的 Op1, Op2, Op3 等对应 operands[0], [1], [2]
            for i, op in enumerate(insn.ops):
                if op.type == ida_ua.o_void: break # 无操作数
                if not self._is_reg_op(op): continue
                
                reg_name = self._get_reg_name(op)
                if reg_name in self.standard_regs: continue # 跳过标准寄存器

                # 判断读/写
                # 这是一个启发式判断，结合 feature 标志位
                is_read = False
                is_write = False

                # 检查 CF_USE (读) 和 CF_CHG (写) 标志
                # 注意：某些指令既读又写 (如 inc)
                
                # 第 i 个操作数的标志位
                if i == 0:
                    if feature & ida_idp.CF_USE1: is_read = True
                    if feature & ida_idp.CF_CHG1: is_write = True
                elif i == 1:
                    if feature & ida_idp.CF_USE2: is_read = True
                    if feature & ida_idp.CF_CHG2: is_write = True
                elif i == 2:
                    if feature & ida_idp.CF_USE3: is_read = True
                    if feature & ida_idp.CF_CHG3: is_write = True

                # --- 核心逻辑：先读后写 ---
                # 如果是读取，且之前没有被定义(写)过 -> 它是潜在参数
                if is_read and reg_name not in defined_regs:
                    candidates.add(reg_name)
                
                # 如果是写入，加入已定义集合
                # 注意：如果一条指令同时读写(如 add $t0, $t0, 1)，
                # 读操作已经在上面处理了(如果$t0没定义，会进candidates)，
                # 然后在这里标记为已定义。
                if is_write:
                    defined_regs.add(reg_name)

        return candidates

    def verify_liveness(self, func_ea, reg_name):
        """
        步骤 2: 基于调用点 (Call-Site) 的活跃性验证
        """
        # 获取所有引用该函数的地方 (Callers)
        callers = list(idautils.CodeRefsTo(func_ea, 0))
        if not callers:
            return False # 无法验证 (可能是间接调用或入口点)

        valid_votes = 0
        
        for call_site in callers:
            # 向前回溯指令，寻找赋值操作
            curr_ea = call_site
            found_def = False
            
            for _ in range(self.BACKTRACK_DEPTH):
                curr_ea = idc.prev_head(curr_ea)
                if curr_ea == idc.BADADDR: break

                insn = idautils.DecodeInstruction(curr_ea)
                if not insn: continue

                # 遇到分支或函数头停止回溯 (简化基本块分析)
                if ida_funcs.get_func(curr_ea).start_ea == curr_ea:
                    break
                if ida_idp.is_call_insn(insn): # 遇到另一个函数调用，停止
                    break

                # 检查是否写入了目标寄存器
                feature = insn.get_canon_feature()
                
                # 遍历操作数寻找写入
                for i, op in enumerate(insn.ops):
                    if op.type == ida_ua.o_void: break
                    if not self._is_reg_op(op): continue
                    
                    op_reg = self._get_reg_name(op)
                    
                    if op_reg == reg_name:
                        # 检查是否是写操作 (CF_CHG)
                        is_write = False
                        if i == 0 and (feature & ida_idp.CF_CHG1): is_write = True
                        if i == 1 and (feature & ida_idp.CF_CHG2): is_write = True
                        
                        if is_write:
                            found_def = True
                            break
                
                if found_def:
                    break
            
            if found_def:
                valid_votes += 1

        # 计算置信度
        confidence = valid_votes / len(callers)
        print(f"DEBUG: {reg_name} liveness: {valid_votes}/{len(callers)} = {confidence}")
        
        return confidence >= self.CONFIDENCE_THRESHOLD


    def analyze_and_fix(self, func_ea):
        """
        主逻辑：结合上述两步
        """
        func_name = idc.get_func_name(func_ea)
        # 1. 扫描
        candidates = self.get_ubd_candidates(func_ea)
        #print(candidates)
        if not candidates:
            return None

        confirmed_args = []
        for reg in candidates:
            # 2. 验证
            if self.verify_liveness(func_ea, reg):
                confirmed_args.append(reg)
                #print(f"[+] Found Hidden Argument in {func_name}: {reg}")

        return confirmed_args


class SignatureAutoFixer:
    def __init__(self):
        pass
    
    def _clean_reg_name(self, reg_name):
        return reg_name.replace("$", "")
    def _get_return_info(self, func_ea):
        tif = ida_typeinf.tinfo_t()
        if not ida_nalt.get_tinfo(tif, func_ea):
            return "int", "<v0>"
        
        ret_type_str = str(tif.get_rettype())
        if ret_type_str == "void":
            return "void", ""
        return ret_type_str, "<v0>"
    def _get_existing_args(self, func_ea):
        existing_args = []
        try:
            cfunc = ida_hexrays.decompile(func_ea)
            if cfunc:
                for arg in cfunc.arguments:
                    type_str = str(arg.type)
                    name_str = arg.name
                    loc_str = ""
                    if arg.location.is_reg():
                        reg_name = ida_idp.get_reg_name(arg.location.reg1(), 4)
                        loc_str = f"<{self._clean_reg_name(reg_name)}>"
                    existing_args.append((type_str, name_str, loc_str))
        except:
            pass
        return existing_args
    def generate_usercall_decl(self, func_ea, new_regs):
        func_name = ida_funcs.get_func_name(func_ea)
        ret_type, ret_loc = self._get_return_info(func_ea)
        args_list = self._get_existing_args(func_ea)
        
        existing_locs = set()
        for _, _, loc in args_list:
            if loc: existing_locs.add(loc.strip("<>"))
        for reg in new_regs:
            clean_reg = self._clean_reg_name(reg)
            if clean_reg not in existing_locs:
                args_list.append(("int", f"hidden_{clean_reg}", f"<{clean_reg}>"))
        
        params_str_parts = [f"{t} {n}{l}" for t, n, l in args_list]
        params_str = ", ".join(params_str_parts)
        decl_str = f"{ret_type} __usercall {func_name}{ret_loc}({params_str});"
        return decl_str
    def apply_and_propagate(self, func_ea, decl_str):
        print(f"[>] Generating Signature: {decl_str}")
        
        # --- IDA 9.0 关键修复开始 ---
        # 1. 创建一个空的 tinfo_t 对象来接收结果
        new_tif = ida_typeinf.tinfo_t()
        
        # 2. 调用 parse_decl
        # 参数1: out_tif (输出对象)
        # 参数2: til (Type Library, None 表示当前数据库)
        # 参数3: decl (C 声明字符串)
        # 参数4: pt_flags (解析标志, PT_SILENT 防止弹窗)
        result = ida_typeinf.parse_decl(new_tif, None, decl_str, 0)
        
        if result is None:
            print(f"[-] Error: Failed to parse declaration.")
            return False
        # --- IDA 9.0 关键修复结束 ---
            
        # 3. 应用类型
        if not ida_typeinf.apply_tinfo(func_ea, new_tif, ida_typeinf.TINFO_DEFINITE):
            print(f"[-] Error: Failed to apply tinfo to {hex(func_ea)}")
            return False
        
        print(f"[+] Applied signature to {hex(func_ea)}")
        # 4. 更新 Callers
        count = 0
        callers = set(idautils.CodeRefsTo(func_ea, 0)) # 去重
        for ref_ea in callers:
            caller_func = ida_funcs.get_func(ref_ea)
            if caller_func:
                try:
                    ida_hexrays.mark_cfunc_dirty(caller_func.start_ea, False)
                    count += 1
                except:
                    pass
                
        print(f"[+] Propagated to {count} callers.")
        return True


def propagate_current_signature(func_ea):
    # 1. 创建空的类型对象
    tif = ida_typeinf.tinfo_t()
    
    # 2. 从 ida_nalt 获取当前函数的类型信息
    if not ida_nalt.get_tinfo(tif, func_ea):
        print(f"[-] 无法获取 {hex(func_ea)} 的类型信息 (可能是单纯的汇编函数或未定义类型)")
        return
    # 获取签名的字符串形式用于显示
    print(f"[+] 当前签名: {str(tif)}")
    # 3. 重新应用该类型 (触发 IDA 内核的类型传播事件)
    # TINFO_DEFINITE (0x0001) 表示这是确定的类型
    if ida_typeinf.apply_tinfo(func_ea, tif, ida_typeinf.TINFO_DEFINITE):
        print("[+] 类型已重新应用，正在通知调用者...")
    else:
        print("[-] 类型应用失败 (可能无需更新)")
    # 4. 找到所有调用者 (Callers) 并强制清除缓存
    caller_funcs = set()
    
    # 遍历引用
    for ref_ea in idautils.CodeRefsTo(func_ea, 0):
        caller = ida_funcs.get_func(ref_ea)
        if caller:
            caller_funcs.add(caller.start_ea)
    if not caller_funcs:
        print("[.] 没有找到调用者。")
        return
    # 确保 Hex-Rays 插件已加载
    if ida_hexrays.init_hexrays_plugin():
        count = 0
        for caller_ea in caller_funcs:
            try:
                # mark_cfunc_dirty(ea, False)
                # False 表示 "invalidate" (使其失效)，迫使下次查看时重新生成微码
                ida_hexrays.mark_cfunc_dirty(caller_ea, False)
                count += 1
            except Exception as e:
                print(f"[-] 刷新 {hex(caller_ea)} 失败: {e}")
        
        print(f"[+] 已刷新 {count} 个调用者。请按 F5 刷新当前视图。")
    else:
        print("[-] Hex-Rays 反编译器不可用，跳过缓存清除。")


# --- 模拟集成到你的 AST Backtrack 流程中的用法 ---

def assembly_check(current_func_ea):
    try:
        fixer = ParamFixer()
        auto_fixer = SignatureAutoFixer()
        
        # 获取当前光标所在的函数，或者遍历所有函数
        # 假设我们正在分析某一个具体的函数
        #current_func_ea = 0x8035746C
        
        # 运行分析
        hidden_args = fixer.analyze_and_fix(current_func_ea)
        if hidden_args:
            print(hidden_args)
            #args_list = fixer._get_existing_args(current_func_ea)
            tif = ida_typeinf.tinfo_t()
            if not ida_nalt.get_tinfo(tif, current_func_ea):
                print("no tinfo")
                return
            print(f"[+] 当前签名: {str(tif)}")
            arg_num = len(str(tif).split(','))
            if arg_num < len(hidden_args):
                print('\n!!!!!!!!!!\nFOUND\n')
        
        #if hidden_args:
            #new_decl = auto_fixer.generate_usercall_decl(current_func_ea, hidden_args)
            #auto_fixer.apply_and_propagate(current_func_ea, new_decl)
        #else:
            #propagate_current_signature(current_func_ea)
    except:
        pass

for func_ea in idautils.Functions():
    func = idaapi.get_func(func_ea)
    print(hex(func_ea))
    assembly_check(func_ea)

