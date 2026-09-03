#!/usr/bin/python
#
# deREferencing - by @danigargu
#

import idc
import idaapi
import ida_idaapi
import ida_typeinf
import ida_idp
import ida_bytes

from dereferencing import dbg
from dereferencing import constants


def is_valid_ea(ea):
    return ea is not None and ea != idc.BADADDR


def get_standard_func_type(funcname):
    named_type = idaapi.get_named_type(None, funcname, idaapi.NTF_SYMM)
    if named_type is None:
        return None

    code, type_str, fields_str, cmt, field_cmts, sclass, value = named_type
    tif = idaapi.tinfo_t()
    tif.deserialize(None, type_str, fields_str, cmt)

    return tif if tif.is_func() else None


def get_api_name(ea):
    name = idc.get_name(ea)
    if name != '':
        values = name.split("_")
        seg_name = idc.get_segm_name(ea)
        if not seg_name or len(values) < 2:
            return None

        seg_name = seg_name.lower()
        if seg_name.startswith(values[0]):
            api_name = ''.join(values[1:])
            return api_name or None
    return None


def get_api_tinfo(ea):
    api_name = get_api_name(ea)
    return get_standard_func_type(api_name) if api_name else None


def get_compiler_name():
    info = ida_idaapi.get_inf_structure()
    return ida_typeinf.get_compiler_name(info.cc.id)


def get_call_displ_dst(ea):
    insn = idaapi.insn_t()
    if idaapi.decode_insn(insn, ea) <= 0:
        return None

    if not idaapi.is_call_insn(insn):
        return None

    if insn.ops[0].type == idc.o_displ:
        reg_name = idaapi.get_reg_name(insn.ops[0].reg, dbg.ptr_size) # ptr_size
        if not reg_name:
            return None

        offset = insn.ops[0].addr
        addr = idaapi.str2ea(f"{reg_name}+{offset}")
        if not is_valid_ea(addr):
            return None

        return dbg.get_ptr(addr)

    return None


def get_import_addr(ea):
    """
    ej:  call rcx ; VirtualProtect
    """
    line = idc.generate_disasm_line(ea, 0)
    if not line:
        return None

    line = idaapi.tag_remove(line)
    parts = line.split("; ")
    if len(parts) == 2 and not parts[1].startswith(("qword_", "dword_")):
        import_addr = idaapi.str2ea(parts[1])
        if is_valid_ea(import_addr):
            return import_addr

    return None


class ArgLoc(object):
    def __init__(self, name=None, typeinf=None, loc=None):
        self.name = name
        self.typeinf = typeinf
        self.loc = loc

    @property
    def size(self):
        return self.typeinf.get_size()
    
    @property
    def is_stack(self):
        return self.loc.atype() == ida_typeinf.ALOC_STACK

    @property
    def is_reg(self):
        return self.loc.atype() == ida_typeinf.ALOC_REG1

    @property
    def decl(self):
        return f'{self.typeinf} {self.name}'
    
    @property
    def type_str(self):
        return f'{self.typeinf}'

    @property
    def reg_name(self):
        return ida_idp.get_reg_name(self.loc.reg1(), self.size)

    @property
    def stack_off(self):
        # self.loc.in_stack()
        if self.loc.has_stkoff():
            return self.loc.stkoff()
        return 0

    @property
    def value(self):
        atype = self.loc.atype()
        if atype == ida_typeinf.ALOC_NONE:
            return None            

        elif atype == ida_typeinf.ALOC_REG1:
            reg_name = ida_idp.get_reg_name(self.loc.reg1(), self.size)
            return idc.get_reg_value(reg_name)

        elif atype == ida_typeinf.ALOC_REG2:
            # register pair (eg: edx:eax [reg2:reg1])
            reg_width = self.size // 2

            reg1_name = ida_idp.get_reg_name(self.loc.reg1(), reg_width)
            reg2_name = ida_idp.get_reg_name(self.loc.reg2(), reg_width)
            reg1_value = idc.get_reg_value(reg1_name)
            reg2_value = idc.get_reg_value(reg2_name)
            
            return (reg2_value << (reg_width * 8)) | reg1_value

        elif atype == ida_typeinf.ALOC_STACK:
            sp = idc.get_reg_value(dbg.registers.stack) 
            stkoff = 0

            if self.loc.has_stkoff():
                stkoff = self.loc.stkoff()

            if self.size == 4:
                return ida_bytes.get_dword(sp+stkoff)
            elif self.size == 8:
                return ida_bytes.get_qword(sp+stkoff)
            else:
                return dbg.get_ptr(sp+stkoff)

        elif atype == ida_typeinf.ALOC_RREL: # untested
            rrel = self.loc.get_rrel()
            reg_name = ida_idp.get_reg_name(rrel.reg, self.size)
            return idc.get_reg_value(reg_name) + rrel.off

        return None

    def __str__(self):
        atype = self.loc.atype()

        if atype == ida_typeinf.ALOC_NONE:
            loc_str = "NONE"

        elif atype == ida_typeinf.ALOC_REG1:
            loc_str = f"REG:{self.reg_name}"

        elif atype == ida_typeinf.ALOC_REG2:
            reg_width = self.size // 2
            r1 = ida_idp.get_reg_name(self.loc.reg1(), reg_width)
            r2 = ida_idp.get_reg_name(self.loc.reg2(), reg_width)
            loc_str = f"REGPAIR:{r2}:{r1}"

        elif atype == ida_typeinf.ALOC_STACK:
            loc_str = f"STACK+0x{self.stack_off:x}"

        elif atype == ida_typeinf.ALOC_RREL:
            rrel = self.loc.get_rrel()
            reg = ida_idp.get_reg_name(rrel.reg, self.size)
            loc_str = f"RREL:{reg}+0x{rrel.off:x}"

        else:
            loc_str = "UNKNOWN"

        val = self.value
        val_str = f"0x{val:x}" if val is not None else "None"

        return (
            f"<name='{self.name}' "
            f"type='{self.typeinf}' "
            f"size={self.size} "
            f"loc='{loc_str}' "
            f"value={val_str}>"
        )


class CallTypeInfo(object):
    def __init__(self, ea):
        self.ea = ea
        self.func_name = None
        self.type_src = None
        self.ret_type = None
        self.ret_reg = None
        self.ret_size = None
        self.cc = None
        self.args = []
        self.has_type = self._init_args()

    def __str__(self):
        if not self.has_type:
            return f"<CallInfo ea={self.ea:#x} name='{self.func_name}' (no prototype)>"

        args_str = ", ".join(arg.decl for arg in self.args)
        return (
            f"<CallTypeInfo ea={self.ea:#x} name='{self.func_name}' "
            f"src='{self.type_src}' ret='{self.ret_type}' retreg='{self.ret_reg}' "
            f"args=[{args_str}]>"
        )

    __repr__ = __str__

    def _fill_from_finfo(self, func_tif, f_info):
        self.ret_type = ida_typeinf.tinfo_t(f_info.rettype)
        self.ret_size = self.ret_type.get_size()
        self.ret_reg = ida_idp.get_reg_name(f_info.retloc.reg1(), self.ret_size)

        self.args = []
        for i in range(func_tif.get_nargs()):
            arg = f_info.at(i)
            arg_name = arg.name
            arg_type = ida_typeinf.tinfo_t(arg.type)
            arg_loc = ida_typeinf.argloc_t(arg.argloc)
            self.args.append(ArgLoc(arg_name, arg_type, arg_loc))

    def _fill_from_tinfo(self, t_info):
        if t_info.is_funcptr():
            func_tif = t_info.get_pointed_object()
        elif t_info.is_func():
            func_tif = t_info
        else:
            return False

        f_info = idaapi.func_type_data_t()
        if not func_tif.get_func_details(f_info):
            return False

        self._fill_from_finfo(func_tif, f_info)
        return True

    def _init_args(self):
        t_info = idaapi.tinfo_t()
        idaapi.get_tinfo(t_info, self.ea)

        if not t_info.empty() and self._fill_from_tinfo(t_info):
            # IDB typedef
            self.type_src = "IDB"
            self.func_name = idc.get_name(self.ea)
            return True
       
        # Standard API typdef
        api_tinfo = get_api_tinfo(self.ea)
        if api_tinfo and not api_tinfo.empty() and self._fill_from_tinfo(api_tinfo):
            self.type_src = "STANDARD_API"
            self.func_name = get_api_name(self.ea) or idc.get_name(self.ea)
            return True
        
        return False


def get_call_dst(ea):
    addr = None
    optype = idc.get_operand_type(ea, 0)
    
    if optype not in [idc.o_mem, idc.o_near, idc.o_reg, idc.o_displ]:
        return addr

    if optype == idc.o_reg:
        regname = idaapi.get_reg_name(idc.get_operand_value(ea, 0), dbg.ptr_size)
        if not regname:
            return None

        addr = idc.get_reg_value(regname)

        import_addr = get_import_addr(ea)
        if import_addr:
            addr = import_addr

    elif optype == idc.o_displ:
        addr = get_call_displ_dst(ea)
    else:
        # optype == idc.o_mem
        addr = idc.get_operand_value(ea, 0)
        ea_name = idc.get_name(addr)
        if ea_name and (ea_name.startswith("dword_") or ea_name.startswith("qword_")):
            ptr = dbg.get_ptr(addr)
            if idaapi.is_loaded(ptr) and idc.get_name(ptr):
                addr = ptr

    return addr if is_valid_ea(addr) else None


def get_call_args(ea):
    call_dst_ea = get_call_dst(ea)
    if call_dst_ea is not None:
        return CallTypeInfo(call_dst_ea)
    return None


def fix_value(value, size):
    masks = {
        1: 0xFF,
        2: 0xFFFF,
        4: 0xFFFFFFFF,
        8: 0xFFFFFFFFFFFFFFFF
    }
    mask = masks.get(size)
    if mask:
        return value & mask
    return value


def fmt_by_size(value, size):
    widths = {
        1: 2,
        2: 4,
        4: 8,
        8: 16
    }
    width = widths.get(size)
    if width is None:
        return f"{value:X}"
    return f"{value:0{width}X}"


def log(s):
    print(f"[{constants.PLUGIN_NAME}] {s}")
