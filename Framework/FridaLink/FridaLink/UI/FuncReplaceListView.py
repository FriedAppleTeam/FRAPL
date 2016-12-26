#
#  FuncReplaceListView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Choose2

class FuncReplaceListView(Choose2):
    def __init__(self, engine, flags=0, width=None, height=None, embedded=False):
        Choose2.__init__(
            self,
            "Replaced Function List",
            [ ["Module", 15], ["Address", 10], ["Symbol", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded
        )

        self.engine = engine
        self.icon = -1
        self.popup_names = ["Insert", "Delete", "Edit", "Refresh"]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]["entry"]

    def OnGetSize(self):
        n = len(self.items)
        return n

    # def OnInsertLine(self):
    #     pass

    def OnDeleteLine(self, n):
        self.engine.handleReplaceFuncDel(self.items[n]["repl_id"])
        return n

    def OnEditLine(self, n):
        self.engine.handleReplaceFuncEdit(self.items[n]["repl_id"])

    # def OnRefresh(self, n):
    #     return n

    def OnGetIcon(self, n):
        return -1        

    # def OnGetLineAttr(self, n):
    #     return [bgcolor, flags=CHITEM_XXXX]

    def setContent(self, content):
        self.items = []
        for key in content:
            entry = content[key]
            replModule = entry.module
            replAddr = "import" if entry.moduleImport == True else "0x%X" % entry.id
            replText = entry.symbol
            self.items.append( { "repl_id": entry.id, "entry": [ replModule, replAddr, replText ] })
        self.Refresh();

    def show(self):
        return self.Show(False) >= 0

__all__ = [
    'FuncReplaceListView'
]
