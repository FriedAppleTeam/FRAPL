#
#  ModuleListView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Choose2

class ModuleListView(Choose2):
    def __init__(self, engine, flags=0, width=None, height=None, embedded=False):
        Choose2.__init__(
            self,
            "Target Module List",
            [ ["Module", 20], ["Base", 10], ["Path", 60], ["Size", 15] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded
        )

        self.items = []
        self.engine = engine
        self.icon = -1
        self.popup_names = []

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        n = len(self.items)
        return n

    # def OnRefresh(self, n):
    #     return n

    def OnGetIcon(self, n):
        return -1        

    # def OnGetLineAttr(self, n):
    #     return [bgcolor, flags=CHITEM_XXXX]

    def setContent(self, content):
        self.items = []
        for module in content:
            moduleName = module["name"]
            moduleBase = module["base"]
            modulePath = module["path"]
            moduleSize = "%d (0x%X)" % (module["size"],module["size"])
            self.items.append( [ moduleName, moduleBase, modulePath, moduleSize ] )

    def show(self):
        return self.Show(False) >= 0

__all__ = [
    'ModuleListView'
]
