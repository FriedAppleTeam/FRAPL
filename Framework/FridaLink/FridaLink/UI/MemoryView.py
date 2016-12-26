#
#  MemoryView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import simplecustviewer_t
from idaapi import COLSTR, SCOLOR_AUTOCMT, SCOLOR_DREF, SCOLOR_VOIDOP, SCOLOR_NUMBER

class MemoryView(simplecustviewer_t):
    def __init__(self, engine, view_id, address):
        super(MemoryView, self).__init__()
        self.engine = engine
        self.view_id = view_id
        self.address = address
        self.lastContent = []

    def Create(self, title):

        if not simplecustviewer_t.Create(self, title):
            return False

        self.menu_fetch = self.AddPopupMenu("Fetch")
        return True

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_fetch:
            self.engine.fetchMemoryRange(self.view_id)
        else:
            # Unhandled
            return False
        return True

    def setContent(self, memory):
        self.ClearLines()
        if memory is None:
            return;
        size = len(memory)

        hdr_title = COLSTR("  Memory for [ ", SCOLOR_AUTOCMT)
        hdr_title += COLSTR("0x%X: %d byte(s)" % (self.address, len(memory)), SCOLOR_DREF)
        hdr_title += COLSTR(" ]", SCOLOR_AUTOCMT)
        self.AddLine(str(hdr_title))
        self.AddLine("")
        self.AddLine(COLSTR("                0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F", SCOLOR_AUTOCMT))

        startAddress = self.address
        line = ""
        chars = ""
        get_char = lambda byte: chr(byte) if 0x20 <= byte <= 0x7E else '.'

        if size != 0:
            for x in range(size):
                if x%16==0:
                    line += COLSTR(" %.12X: " % startAddress, SCOLOR_AUTOCMT)
                if len(self.lastContent) == len(memory):
                    if memory[x] != self.lastContent[x]:
                        line += COLSTR(str("%.2X " % memory[x]), SCOLOR_VOIDOP)
                        chars += COLSTR(get_char(memory[x]), SCOLOR_VOIDOP)
                    else:
                        line += COLSTR(str("%.2X " % memory[x]), SCOLOR_NUMBER)
                        chars += COLSTR(get_char(memory[x]), SCOLOR_NUMBER)
                else:
                    line += COLSTR(str("%.2X " % memory[x]), SCOLOR_NUMBER)
                    chars += COLSTR(get_char(memory[x]), SCOLOR_NUMBER)

                if (x+1)%16==0:
                    line += "  " + chars
                    self.AddLine(line)
                    startAddress += 16
                    line = ""
                    chars = ""

            # add padding
            tail = 16 - size%16
            if tail != 0:
                for x in range(tail): line += "   "
                line += "  " + chars
                self.AddLine(line)

        self.Refresh()
        self.lastContent = memory
    
    def OnClose(self):
        self.engine.memoryViewClosed(self.view_id)

__all__ = [
    'MemoryView'
]

