#!/usr/bin/python
#
# deREferencing - by @danigargu
#

import idc
import idaapi

from dereferencing import dbg, utils, config, win2_errors, actions
from dereferencing.qt_compat import QtCore, QtWidgets
from dereferencing.views import CustViewer
from dereferencing.constants import PLUGIN_NAME, REGS_WIDGET_TITLE


class RegistersViewer(CustViewer):
    def __init__(self, parent):
        super(RegistersViewer, self).__init__()
        self.parent     = parent
        self.title      = None
        self.last_error = None
        self.actions    = None
        self.args_info  = None
        self.args_lineo = None
        self.menu_actions = []

    def add_legend(self):
        self.add_line()
        self.add_line(self.as_stack('STACK') + ' | ' +
            self.as_heap('HEAP') + ' | ' +
            self.as_code('CODE') + ' | ' +
            self.as_data('DATA') + ' | ' +
            self.as_rodata('RODATA') + ' | ' +
            self.as_rwx('RWX') + ' | ' +
            self.as_value('VALUE')
        )

    def add_line(self, s=None, highlight=False):
        if not s:
            s = ""
        bgcolor = config.HIGHLIGHT_COLOR if highlight and config.HIGHLIGHT_COLOR else None
        self.AddLine(s, bgcolor=bgcolor)

    def last_error_str(self):
        result = None
        changed = False
        last_error = dbg.get_last_error()

        if last_error is not None:
            if last_error != self.last_error:
                result = '*'
                changed = True
            else:
                result = ' '

            result += f"GLE {self.as_value(dbg.format_ptr(last_error))}"
            error_name = win2_errors.error_code_to_name(last_error)
            if error_name:
                result += f" ({error_name})"

            self.last_error = last_error
        return result, changed

    def colorize_call_arg(self, arg, max_length):
        arg_size = arg.size
        arg_type_str = arg.type_str
        arg_value = arg.value

        if arg_value is None:
            color_value = self.as_comment("<unavailable>")
        elif arg_size not in (1, 2, 4, 8):
            color_value = self.as_comment(f"<unsupported size:{arg_size}>")
        else:
            value = utils.fix_value(arg_value, arg_size)
            color_value = self.colorize_by_type(value, arg_size)

        arg_str = arg_type_str + " " + arg.name
        arg_str = arg_str.ljust(max_length, " ")

        result = f"{arg_str} | {color_value}"
        self.add_line(result)

    def calc_max_length_args_names(self, args):
        lengths = []
        for arg in args:
            arg_str = None

            if len(arg.name) == 0:
                arg_str = arg.type_str
            else:
                arg_str = arg.decl
            lengths.append(len(arg_str))
        return max(lengths) + 1
    

    def parse_call_args(self, pc):
        self.args_info = utils.get_call_args(pc)
        if self.args_info is None or not self.args_info.has_type:
            return

        func_name = self.args_info.func_name
        args = self.args_info.args
        n_args = len(args)

        self.add_line()
        prolog = f"━━━━ CALL {self.as_code(func_name)} ━━━━"
        self.add_line(prolog)

        self.args_lineo = self.Count()

        if n_args > 0:
            max_length = self.calc_max_length_args_names(args)

            for arg in args:
                self.colorize_call_arg(arg, max_length)

    def parse_return_address(self, insn):
        if not idaapi.is_ret_insn(insn):
            return
        
        if insn.ops[0].type not in [idaapi.o_void, idaapi.o_imm]:
            return

        offset = 0
        if insn.ops[0].type == idaapi.o_imm:
            offset = insn.ops[0].value

        stack_reg = dbg.registers.stack
        stack_str = f"{stack_reg}+{offset:x}"
        sp = idc.get_reg_value(stack_reg)
        ret_addr = dbg.get_ptr(sp + offset)
        
        self.add_line()
        self.add_line(f"━━━━ RETURN ADDRESS [{stack_str}] ━━━━")
        self.add_line(" " + self.parse_value(ret_addr))

    def parse_value(self, value):
        return self.format_pointer_chain(value, stack_view=False)

    def reload_info(self):
        if not dbg.is_process_suspended():
            return False

        self.ClearLines()
        self.args_info = None
        self.args_lineo = None
        dbg.set_thread_info()

        for reg in dbg.registers:
            line, changed = self.colorize_register(reg)
            if line is not None:
                self.add_line(line, changed)

        if dbg.is_pefile:
            self.add_line(*self.last_error_str())

        pc = idc.get_reg_value(dbg.registers.pc)
        insn = idaapi.insn_t()
        if idaapi.decode_insn(insn, pc) <= 0:
            return False

        # call - parse arguments
        if idaapi.is_call_insn(insn):
            if config.PARSE_CALL_ARGS:# and dbg.ptr_size == 8:
                self.parse_call_args(pc)

        # ret - parse return address
        elif idaapi.is_ret_insn(insn):
            if config.SHOW_RETURN_ADDR:
                self.parse_return_address(insn)

        if config.SHOW_LEGEND:
            self.add_legend()
        return True

    def get_reg_label(self, reg, val):
        changed = False
        if self.reg_vals[reg] != val:
            regname = f"*{reg}"
            self.reg_vals[reg] = val
            changed = True
        else:
            regname = f" {reg}"
        regname = regname.ljust(dbg.registers.max_len+2)
        return regname, changed

    def colorize_register(self, reg):
        result = ''
        reduced = False

        try:
            reg_val = idc.get_reg_value(reg)
        except Exception:
            return None, False

        label, changed = self.get_reg_label(reg, reg_val)
        chain = self.get_ptr_chain(reg_val)

        result += label + self.colorize_value(chain[0])

        if reg == dbg.registers.flagsr:
            return result, changed

        elif reg != dbg.registers.pc:
            vals = chain[1:]
            if len(vals) > config.MAX_DEREF_LEVELS:
                vals = vals[:config.MAX_DEREF_LEVELS]
                reduced = True

            result += ''.join([self.as_ptr(value) for value in vals])
            if reduced:
                result += self.as_arrow_string("[...]")

        result += self.get_value_info(chain[-1])
        if chain.limit_exceeded:
            result += self.as_arrow_string("[...]")

        return result, changed

    def modify_value(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        reg_val = idc.get_reg_value(reg)
        b = idaapi.ask_str("0x%X" % reg_val, 0, "Modify register value")
        if b is None:
            return
        
        try:
            value = int(idaapi.str2ea(b))
            idc.set_reg_value(value, reg)
            self.reload_info()

            if reg == dbg.registers.flags:
                self.reload_flags_view()
        except Exception:
            idaapi.warning("Invalid expression")

    def reload_flags_view(self):
        if self.parent.flags_view:
            self.parent.flags_view.reload_info()

    def get_selected_reg(self):
        reg = None
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers)-1:
            return reg

        line = self.GetLine(lineno)
        if line and len(line) > 0:
            line_str = idaapi.tag_remove(line[0])
            reg = line_str[1:dbg.registers.max_len+2].strip()
        return reg

    def toggle_value(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        val = dbg.to_uint(~self.reg_vals[reg])
        idc.set_reg_value(val, reg)
        self.reload_info()

    def inc_reg(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        val = dbg.to_uint(self.reg_vals[reg]+1)
        idc.set_reg_value(val, reg)
        self.reload_info()

    def dec_reg(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        val = dbg.to_uint(self.reg_vals[reg]-1)
        idc.set_reg_value(val, reg)
        self.reload_info()

    def zero_reg(self):
        reg = self.get_selected_reg()
        if not reg:
            return

        idc.set_reg_value(0, reg)
        self.reload_info()

    def set_deref_levels(self):
        value = idaapi.ask_long(config.MAX_DEREF_LEVELS, "Set current dereferencing levels to show")
        if value is None:
            return False
        
        if value < 0:
            idaapi.warning("Negative values are not allowed")
            return False

        if value > config.DEREF_LIMIT:
            idaapi.warning(f"Value should not exceed the dereferencing limit: {config.DEREF_LIMIT}")
            return False

        config.MAX_DEREF_LEVELS = value
        self.reload_info()
        return True
    

    def pause_dbghooks(self):
        config.PAUSE_DBGHOOKS = (not config.PAUSE_DBGHOOKS)
        if config.PAUSE_DBGHOOKS:
            self.parent.hook.unhook()
        else:
            self.parent.hook.hook()

    def set_show_area_name(self):
        config.SHOW_AREA_NAME = (not config.SHOW_AREA_NAME)
        self.reload_info()

    def set_show_legend(self):
        config.SHOW_LEGEND = (not config.SHOW_LEGEND)
        self.reload_info()

    def register_actions(self): 
        self.menu_actions.extend([
            actions.MenuAction("-"),
            actions.MenuAction("jump_disassembly", self.jump_in_disassembly, "Jump in disassembly",  None, "J",         124),
            actions.MenuAction("jump_new_window",  self.jump_in_new_window,  "Jump in a new window", None, "Ctrl-J",    125),
            actions.MenuAction("jump_hex",         self.jump_in_hex,         "Jump in hex",          None, "X",         89),
            actions.MenuAction("modify_value",     self.modify_value,        "Modify value",         None, "E",         104),
            actions.MenuAction("toggle_value",     self.toggle_value,        "Toggle value",         None, "Alt-Space", 58),
            actions.MenuAction("inc_value",        self.inc_reg,             "Increment value",      None, "+",         50),
            actions.MenuAction("dec_value",        self.dec_reg,             "Decrement value",      None, "-",         51),
            actions.MenuAction("zero_value",       self.zero_reg,            "Zero value",           None, "0",         123),
            actions.MenuAction("dump_memory",      self.dump_memory,         "Dump memory",          None, "Ctrl-D",    3),
            actions.MenuAction("-"),
            actions.MenuAction("update",           self.reload_info,         "Update view",          None, "U",  0, always_enabled=True),
            actions.MenuAction("show_legend",      self.set_show_legend,     "Show legend",          None, None, checkable=config.SHOW_LEGEND),
            actions.MenuAction("show_area_name",   self.set_show_area_name,  "Show area name",       None, None, checkable=config.SHOW_AREA_NAME),
            actions.MenuAction("deref_levels",     self.set_deref_levels,    "Dereferencing levels", None, None, always_enabled=True),
            actions.MenuAction("pause_dbghooks",   self.pause_dbghooks,      "Pause hooks",          None, None, checkable=config.PAUSE_DBGHOOKS),
            actions.MenuAction("-"),
        ])
        actions.register_menu_actions(self)

    def unregister_actions(self):
        actions.unregister_menu_actions(self)

    def can_edit_line(self):
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers)-1:
            return False
        return True

    def Create(self, title):
        self.title = title

        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.reg_vals  = dict([(i, None) for i in dbg.registers])
        self.register_actions()
        return True

    def OnKeydown(self, vkey, shift):
        if vkey == 27: # ESC
            pass
        else:
            return False
        return True

    def OnDblClick(self, shift):
        symbol = self.get_current_word()
        if symbol is not None:
            if symbol.isupper() and symbol.replace("*","") in dbg.registers:
                self.modify_value()
                return True
            else:
                ea = self.resolve_expr(symbol)
                if ea and idaapi.is_loaded(ea):
                    idaapi.jumpto(ea)
                    return True
        return False

    def OnHint(self, lineno):
        if self.args_lineo is None or self.args_info is None:
            return False

        if not dbg.is_process_suspended() or dbg.registers.pc is None:
            return False

        # Is call?
        try:
            pc = idc.get_reg_value(dbg.registers.pc)
            insn = idaapi.insn_t()
            if idaapi.decode_insn(insn, pc) <= 0:
                return False
        except Exception:
            return False

        # call - parse arguments
        if not idaapi.is_call_insn(insn):
            return False

        if lineno >= self.args_lineo:
            idx = lineno - self.args_lineo
            args = self.args_info.args
            if idx > len(args)-1:
                return False
            
            return (1, f"{args[idx]}")
        
        return False

    def OnClose(self):
        self.unregister_actions()


class FlagsView(CustViewer):
    def __init__(self, parent):
        super(FlagsView, self).__init__()
        self.parent = parent
        self.menu_actions = []

    def Create(self, title):
        if not idaapi.simplecustviewer_t.Create(self, title):
            return False

        self.flag_vals  = dict([(i,None) for i in dbg.registers.flags])
        self.register_actions()

        return True

    def reload_info(self):
        if not dbg.is_process_suspended():
            return False

        self.ClearLines()
        for flag in dbg.registers.flags:
            try:
                value = idc.get_reg_value(flag)
            except Exception:
                continue

            if self.flag_vals.get(flag) != value:
                result = self.as_changed(str(value))
                self.flag_vals[flag] = value
            else:
                result = str(value)

            self.add_line('%-4s %s' % (flag, result))

        return True

    def as_changed(self, s):
        return idaapi.COLSTR(s, idaapi.SCOLOR_CREFTAIL)

    def add_line(self, s=None):
        if not s:
            s = ""
        self.AddLine(s)

    def switch_value(self):
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers.flags):
            return

        line = self.GetLine(lineno)
        line = idaapi.tag_remove(line[0])
        flag = line[:4].strip()
        new_val = not self.flag_vals[flag]

        rc = idc.set_reg_value(int(new_val), flag)
        if not rc:
            idaapi.warning("Unable to update the register value")
            return

        self.parent.reload_view()

    def can_edit_line(self):
        lineno = self.GetLineNo()
        if lineno > len(dbg.registers.flags):
            return False
        return True

    def register_actions(self):
        self.menu_actions.extend([
            actions.MenuAction("-"),
            actions.MenuAction("switch_value", self.switch_value, "Switch value",  None, "S", 104),
            actions.MenuAction("-")
        ])
        actions.register_menu_actions(self)

    def unregister_actions(self):
        actions.unregister_menu_actions(self)

    def OnClose(self):
        self.unregister_actions()


class MySplitter(QtWidgets.QSplitter):
    def __init__(self, parent=None, flags_width=config.FLAGS_WIDTH):
        super(MySplitter, self).__init__(QtCore.Qt.Horizontal, parent)
        self._flags_width = flags_width
        self._inited = False

    def showEvent(self, e):
        super(MySplitter, self).showEvent(e)
        if self._inited or self.count() != 2:
            return

        total = self.width()
        if total <= 0:
            return

        right = min(self._flags_width, total)
        left = max(0, total - right)
        self.setSizes([left, right])
        self._inited = True


class RegsFlagsViewer(idaapi.PluginForm):
    def __init__(self):
        super(RegsFlagsViewer, self).__init__()
        self.hook = None
        self.flags_view = None
        self.flagsview_widget = None
        self.regsview_widget = None
        dbg.initialize()

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.PopulateForm()

        self.hook = dbg.DbgHooks(self.reload_view)
        self.hook.hook()

    def reload_view(self):
        self.regs_view.reload_info()

        if self.flags_view:
            self.flags_view.reload_info()

    def PopulateForm(self):
        hbox = QtWidgets.QHBoxLayout()
        splitter = MySplitter(self.parent)

        hbox.setContentsMargins(0, 0, 0, 0)

        self.regs_view = RegistersViewer(self)
        self.regs_view.Create(f"{PLUGIN_NAME}-Registers")
        self.regs_view.hide_ida_status_bar()

        show_flags = (dbg.registers.flags is not None)

        if show_flags:
            self.flags_view = FlagsView(self)
            self.flags_view.Create(f"{PLUGIN_NAME}-Flags")
            self.flags_view.hide_ida_status_bar()
            self.flagsview_widget = self.FormToPyQtWidget(self.flags_view.GetWidget())

        self.regsview_widget = self.FormToPyQtWidget(self.regs_view.GetWidget())
        
        splitter.setHandleWidth(1)
        splitter.addWidget(self.regsview_widget)

        if self.flagsview_widget:
            self.flagsview_widget.setMinimumWidth(config.FLAGS_WIDTH)
            splitter.addWidget(self.flagsview_widget)

        hbox.addWidget(splitter)
        self.parent.setLayout(hbox)

        self.reload_view()

    def set_window_position(self):
        ref_widgets = [
            ("Modules",       idaapi.DP_TOP),
            ("Threads",       idaapi.DP_TOP),
            ("IDA View-EIP",  idaapi.DP_RIGHT),
            ("Stack view",    idaapi.DP_TOP)
        ]
        plug_window_name = f"Registers - {PLUGIN_NAME}"
        regs_widget = idaapi.find_widget("General registers")

        if regs_widget:
            idaapi.set_dock_pos(REGS_WIDGET_TITLE, "General registers", idaapi.DP_INSIDE)
            #idaapi.close_widget(regs_widget, 0)
        else:
            found = False
            for wname, pos in ref_widgets:
                if idaapi.find_widget(wname):
                    idaapi.set_dock_pos(REGS_WIDGET_TITLE, wname, pos)
                    found = True
                    break
            if not found:
                idaapi.set_dock_pos(REGS_WIDGET_TITLE, None, idaapi.DP_FLOATING)

    def OnClose(self, form):
        if self.hook:
            self.hook.unhook()
