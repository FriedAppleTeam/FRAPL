#
#  CPUContextView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import simplecustviewer_t
from idaapi import COLSTR, SCOLOR_AUTOCMT, SCOLOR_DREF, SCOLOR_INSN, SCOLOR_VOIDOP, SCOLOR_REG, SCOLOR_NUMBER

from ..Settings.SettingsStorage import SettingsStorage as FrLSettings

class CPUContextView(simplecustviewer_t):
    def __init__(self, engine, view_id, command):
        super(CPUContextView, self).__init__()
        self.engine = engine
        self.view_id = view_id
        self.command = command
        self.lastContext = None
        self.lastArch = None
        self.columns = None

    def Create(self, title):

        if not simplecustviewer_t.Create(self, title):
            return False

        self.menu_cols1 = self.AddPopupMenu("1 Column")
        self.menu_cols2 = self.AddPopupMenu("2 Columns")
        self.menu_cols3 = self.AddPopupMenu("3 Columns")
        return True

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_cols1:
            self.columns = 1
        elif menu_id == self.menu_cols2:
            self.columns = 2
        elif menu_id == self.menu_cols3:
            self.columns = 3
        else:
            # Unhandled
            return False
        if self.lastArch is not None and self.lastContext is not None:
            self.setContent({"arch":self.lastArch, "context":self.lastContext})
        return True

    def getRegisterOrder(self, arch):
        registers = {
            "arm"   : ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r11", "r12", "pc", "sp", "lr"],
            "arm64" : ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7", "x8", "x9", "x10","x11","x12","x13","x14","x15", "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23", "x24","x25", "x26", "x27", "x28", "pc", "sp","fp", "lr"],
            "ia32"  : [],
            "x64"   : ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "pc", "rip", "sp"],
        }
        return registers[arch]     

    def setContent(self, content):
        global gSettings_CpuCtxCols

        arch = content["arch"]
        context = content["context"]

        self.ClearLines()

        hdr_title = COLSTR("  CPU context for [ ", SCOLOR_AUTOCMT)
        hdr_title += COLSTR("0x%X: " % self.view_id, SCOLOR_DREF)
        hdr_title += COLSTR(self.command, SCOLOR_INSN)
        hdr_title += COLSTR(" ]", SCOLOR_AUTOCMT)
        self.AddLine(hdr_title)
        self.AddLine("")

        if len(context) == 0 or arch == "":
            self.Refresh()
            return

        if self.columns is None:
            cols = FrLSettings().getCpuContextColumns()
        else:
            cols = self.columns
        regList = self.getRegisterOrder(arch)
        reg_cnt = len(regList)
        lines = reg_cnt/cols if reg_cnt%cols==0 else (reg_cnt/cols) + 1
        line = ""
        for i in range(lines):
            if i != 0:
                self.AddLine(line)
                line = ""

            for j in xrange(i, reg_cnt, lines):
                reg = regList[j]
                line = line + COLSTR(" %4s: " % str(reg), SCOLOR_REG)
                if self.lastContext is not None:
                    if self.lastContext[reg] != context[reg]:
                        line += COLSTR(str(context[reg]), SCOLOR_VOIDOP)
                    else:
                        line += COLSTR(str(context[reg]), SCOLOR_NUMBER)
                else:
                    line += COLSTR(str(context[reg]), SCOLOR_NUMBER)

                line = line.ljust(35 * ((j/lines) + 1))

        self.AddLine(line)

        self.Refresh()
        self.lastContext = context
        self.lastArch = arch

    def OnClose(self):
        self.engine.cpuViewClosed(self.view_id)

__all__ = [
    'CPUContextView'
]
