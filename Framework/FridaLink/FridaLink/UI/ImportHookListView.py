#
#  ImportHookListView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Choose2

class ImportHookListView(Choose2):
    def __init__(self, engine, flags=0, width=None, height=None, embedded=False):
        Choose2.__init__(
            self,
            "Import Hook List",
            [ ["Module", 15], ["Symbol", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded
        )

        self.engine = engine
        self.icon = -1
        self.popup_names = ["Show", "Delete", "Edit", "Refresh"]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]["entry"]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnInsertLine(self):  # use to show
        pass

    def OnDeleteLine(self, n):
        self.engine.handleUnhookImportSymbol(self.items[n]["hook_id"])
        return n

    def OnEditLine(self, n):
        self.engine.handleEditImportSymbolHook(self.items[n]["hook_id"])

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
            hookModule = entry.hook.module
            hookText = entry.hook.symbol
            self.items.append( { "hook_id": entry.hook.id, "entry": [ hookModule, hookText ] })
        self.Refresh();

    def show(self):
        return self.Show(False) >= 0

__all__ = [
    'ImportHookListView'
]
