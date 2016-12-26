#
#  BacktraceView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import simplecustviewer_t
from idaapi import COLSTR, SCOLOR_AUTOCMT, SCOLOR_DREF, SCOLOR_DEMNAME, SCOLOR_SEGNAME, SCOLOR_NUMBER, SCOLOR_CREFTAIL

class BacktraceView(simplecustviewer_t):
    def __init__(self, engine, view_id):
        super(BacktraceView, self).__init__()
        self.engine = engine
        self.view_id = view_id

    def setContent(self, backtrace):
        self.ClearLines()
        if backtrace is None:
            return;
        hdr_title = COLSTR("  Backtrace for [ ", SCOLOR_AUTOCMT)
        hdr_title += COLSTR("0x%X: " % self.view_id, SCOLOR_DREF)
        hdr_title += COLSTR(backtrace.getEntry(0).sym_name, SCOLOR_DEMNAME)
        hdr_title += COLSTR(" ]", SCOLOR_AUTOCMT)
        self.AddLine(str(hdr_title))
        self.AddLine("")
        for idx in range(backtrace.getCount()):
            if idx == 0:
                continue
            entry = backtrace.getEntry(idx)
            if entry is None:
                continue
            call = COLSTR(" %4d: " % idx, SCOLOR_AUTOCMT)
            call += COLSTR(entry.mod_name.ljust(30), SCOLOR_SEGNAME) + " "
            if entry.idb_addr:
                addr_color = SCOLOR_NUMBER
            else:
                addr_color = SCOLOR_CREFTAIL
            call += COLSTR(str("0x%.12X" % entry.sym_addr), addr_color) + COLSTR(" + ", SCOLOR_AUTOCMT)
            call += COLSTR(str("0x%.6X" % (entry.sym_call - entry.sym_addr)) + " ", addr_color)
            call += COLSTR(entry.sym_name, SCOLOR_DEMNAME)
            self.AddLine(str(call))
        self.Refresh()

    def OnClose(self):
        self.engine.backtraceViewClosed(self.view_id)

__all__ = [
    'BacktraceView'
]
