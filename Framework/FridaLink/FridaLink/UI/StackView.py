#
#  StackView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import simplecustviewer_t
from idaapi import COLSTR, SCOLOR_AUTOCMT, SCOLOR_DREF, SCOLOR_INSN, SCOLOR_VOIDOP, SCOLOR_NUMBER, SCOLOR_SEGNAME, SCOLOR_DEMNAME

class StackView(simplecustviewer_t):
    def __init__(self, engine, view_id, command):
        super(StackView, self).__init__()
        self.engine = engine
        self.view_id = view_id
        self.command = command
        self.lastContent = {}

    def setContent(self, stack):
        self.ClearLines()
        if stack is None:
            return;
        hdr_title = COLSTR("  Stack for [ ", SCOLOR_AUTOCMT)
        hdr_title += COLSTR("0x%X: " % self.view_id, SCOLOR_DREF)
        hdr_title += COLSTR(self.command, SCOLOR_INSN)
        hdr_title += COLSTR(" ]", SCOLOR_AUTOCMT)
        self.AddLine(hdr_title)
        self.AddLine("")

        num = stack.getCount()
        for i in xrange(0, num):
            addr, data, symbol, sp = stack.getEntry(i)
            line = " "
            if sp:
                line += COLSTR("%.16X" % addr, SCOLOR_DREF) 
            else:
                line += COLSTR("%.16X" % addr, SCOLOR_AUTOCMT) 
            line += "  "
            if addr in self.lastContent and self.lastContent[addr] != data:
                line += COLSTR("%.16X" % data, SCOLOR_VOIDOP)
            else:
                line += COLSTR("%.16X" % data, SCOLOR_NUMBER)
            info = self.engine.resolveStackAddress(data, symbol)
            if info is not None:
                if 'module' in info:
                    line += "  "
                    line += COLSTR(info['module'], SCOLOR_SEGNAME)
                    if 'symbol' in info:
                        line += COLSTR(":", SCOLOR_AUTOCMT)
                        line += COLSTR(info['symbol'], SCOLOR_DEMNAME)

            self.AddLine(line)
            self.lastContent[addr] = data

        self.Refresh()

    def OnClose(self):
        self.engine.backtraceViewClosed(self.view_id)

__all__ = [
    'StackView'
]
