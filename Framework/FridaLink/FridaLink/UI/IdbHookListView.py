#
#  IdbHookListView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Choose2

class IdbHookListView(Choose2):
    def __init__(self, engine, flags=0, width=None, height=None, embedded=False):
        Choose2.__init__(
            self,
            "IDB Hook List",
            [ ["Module", 15], ["Type", 5], ["Address", 10], ["Command/Symbol", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded
        )

        self.engine = engine
        self.icon = -1
        self.popup_names = ["Jump To", "Delete", "Edit", "Refresh"]

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]["entry"]

    def OnGetSize(self):
        n = len(self.items)
        return n

    def OnInsertLine(self):  # use to jump to disasm
        # ea = self.items[n]["hook_id"]
        # Jump(ea)
        pass

    def OnDeleteLine(self, n):
        hookType = self.items[n]["entry"][1]
        if hookType == "inst":
            self.engine.handleUnhookInst(self.items[n]["hook_id"])
        elif hookType == "func":
            self.engine.handleUnhookFunc(self.items[n]["hook_id"])
        return n

    def OnEditLine(self, n):
        hookType = self.items[n]["entry"][1]
        if hookType == "inst":
            self.engine.handleHookInstEdit(self.items[n]["hook_id"])
        elif hookType == "func":
            self.engine.handleHookFuncEdit(self.items[n]["hook_id"])

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
            hookType = entry.hook.type
            hookAddress = "0x%X" % entry.hook.id
            if hookType == "inst":
                hookText = entry.hook.mnemonic
            elif hookType == "func":
                hookText = entry.hook.symbol
            self.items.append( { "hook_id": entry.hook.id, "entry": [ hookModule, hookType, hookAddress, hookText ] })
        self.Refresh();

    def show(self):
        return self.Show(False) >= 0

__all__ = [
    'IdbHookListView'
]
