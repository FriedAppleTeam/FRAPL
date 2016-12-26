#
#  AppLogView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import COLSTR, SCOLOR_AUTOCMT
from idaapi import simplecustviewer_t

class AppLogView(simplecustviewer_t):
    def __init__(self):
        super(AppLogView, self).__init__()

    def Create(self, title):

        if not simplecustviewer_t.Create(self, title):
            return False

        self.menu_clear = self.AddPopupMenu("Clear")
        return True

    def OnPopupMenu(self, menu_id):
        if menu_id == self.menu_clear:
            self.ClearLines()
        else:
            # Unhandled
            return False
        return True

    def addEntry(self, header, hdr_color, log_entry):
        lines = log_entry.splitlines()
        header = COLSTR(header, hdr_color)
        self.AddLine(header + COLSTR(": " + str(lines[0]), SCOLOR_AUTOCMT))
        del lines[0]
        for line in lines:
            self.AddLine(COLSTR(str(line), SCOLOR_AUTOCMT))

__all__ = [
    'AppLogView'
]
