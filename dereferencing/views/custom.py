#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# deREferencing - by @danigargu
#

import re

import idc
import idaapi
import ida_kernwin

from dereferencing import dbg
from dereferencing.qt_compat import QtCore, QtWidgets
from dereferencing.colorizer import Colorizer


class StatusHider(QtCore.QObject):
    def eventFilter(self, obj, event):
        if event.type() in (QtCore.QEvent.Show,
                            QtCore.QEvent.Resize,
                            QtCore.QEvent.LayoutRequest):
            obj.setMinimumHeight(0)
            obj.setMaximumHeight(0)
            obj.hide()
        return False


class CustViewer(idaapi.simplecustviewer_t, Colorizer):
    def __init__(self):
        idaapi.simplecustviewer_t.__init__(self)
        Colorizer.__init__(self)

    def get_current_word(self):
        word = self.GetCurrentWord()
        if word:
            word = idaapi.tag_remove(word)
        return word

    def resolve_expr(self, expr):
        res = None
        try:
            expr = re.sub(r'[(|)]', '', expr)
            res = int(expr, 16)
        except ValueError:
            segm = idaapi.get_segm_by_name(expr)
            if segm:
                res = segm.start_ea
            else:
                ea = idaapi.str2ea(expr)
                if ea != idc.BADADDR:
                    res = ea
        return res

    def get_current_expr_ea(self):
        ea = None
        symbol = self.get_current_word()
        if symbol:
            ea = self.resolve_expr(symbol)
        return ea

    def jump_in_disassembly(self):
        ea = self.get_current_expr_ea()
        if not ea or not idaapi.is_loaded(ea):
            idaapi.warning("Unable to resolve current expression\n")
            return

        widget = self.find_disass_view()
        if not widget:
            idaapi.warning("Unable to find disassembly view")
            return

        self.jumpto_in_view(widget, ea)

    def jump_in_new_window(self):
        ea = self.get_current_expr_ea()
        if not ea or not idaapi.is_loaded(ea):
            return
        
        window_name = f"D-{ea:#x}"
        widget = idaapi.open_disasm_window(window_name)
        if widget:
            self.jumpto_in_view(widget, ea)
        else:
            idaapi.warning("Unable to create the new window")

    def jump_in_hex(self):
        ea = self.get_current_expr_ea()
        if not ea or not idaapi.is_loaded(ea):
            idaapi.warning("Unable to resolve current expression\n")
            return

        widget = self.find_hex_view()
        if not widget:
            idaapi.warning("Unable to find hex view")
            return
        self.jumpto_in_view(widget, ea)

    def find_disass_view(self):
        widget = idaapi.find_widget(f'IDA View-{dbg.registers.pc}')
        if widget:
            return widget

        widget = idaapi.find_widget('IDA View-EIP') # IDA < 9.0 called the windows "IDA View-EIP" even for x64 targets
        if widget:
            return widget

        for c in map(chr, range(65, 91)):
            widget = idaapi.find_widget(f'IDA View-{c}')
            if widget:
                return widget
        return None

    def find_hex_view(self):
        for i in range(1, 10):
            widget = idaapi.find_widget('Hex View-%d' % i)
            if widget:
                return widget
        return None

    def jumpto_in_view(self, view, ea):
        idaapi.activate_widget(view, True)
        return idaapi.jumpto(ea)
    

    def dump_memory(self):
        word = self.get_current_word()
        if word is None:
            return
               
        ea = self.resolve_expr(word)
        if ea is None or not idc.is_loaded(ea):
            return

        size = idaapi.ask_long(dbg.ptr_size, f"{ea:#x} - Enter dump size")
        if size is None or size == 0:
            return
        
        output_file = idaapi.ask_file(True, '*', 'Enter the path to save the dump')
        if output_file is None:
            return
        
        try:
            data = idc.get_bytes(ea, size, True)
            with open(output_file, 'wb') as f:
                f.write(data)

            idaapi.info(f"{len(data)} bytes dumped from {ea:#x} to {output_file}")
        except Exception as e:
            idaapi.warning(e)
        
    

    def hide_ida_status_bar(self):
        qwidget = ida_kernwin.PluginForm.TWidgetToPyQtWidget(self.GetWidget())
        status = qwidget.findChild(QtWidgets.QStatusBar)

        if status:
            self._status_hider = StatusHider(qwidget)
            status.installEventFilter(self._status_hider)

            status.setMinimumHeight(0)
            status.setMaximumHeight(0)
            status.hide()
