#
#  MemoryManagerView.py
#  FridaLink UI
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Choose2

from ..UI.AddMemoryRangeDialog import AddMemoryRangeDialog

class MemoryManagerView(Choose2):
    def __init__(self, engine, flags=0, width=None, height=None, embedded=False):
        Choose2.__init__(
            self,
            "Memory Manager",
            [ ["Address", 20], ["Size", 10], ["Comment", 30] ],
            flags = flags,
            width = width,
            height = height,
            embedded = embedded
        )

        self.engine = engine
        self.linkList = []
        self.icon = -1
        self.popup_names = ["Insert...", "Delete", "Show", "Refresh"]

    def OnClose(self):
        pass

    def OnInsertLine(self):
        addRangeDlg = AddMemoryRangeDialog()
        addRangeDlg.Compile()
        addRangeDlg.mem_addr.value = 0x0
        addRangeDlg.mem_size.value = 16
        ok = addRangeDlg.Execute()
        if ok == 1:
            mem_addr = addRangeDlg.mem_addr.value
            mem_size = addRangeDlg.mem_size.value
            mem_cmnt = addRangeDlg.mem_cmnt.value
            self.engine.addMemoryRegion(mem_addr, mem_size, mem_cmnt)

    def OnDeleteLine(self, n):
        if n < 0:
            return n
        self.engine.delMemoryRegion(self.items[n]['mem_id'])
        return n

    def OnEditLine(self, n):  # use to display MemoryView
        self.engine.showMemoryView(self.items[n]['mem_id'])

    def OnSelectionChange(self, sel_list):
        self.linkList = []
        for item in sel_list:
            self.linkList.append(self.items[item-1]['mem_id'])

    # def OnSelectLine(self, n):
    #     pass

    def OnGetLine(self, n):
        return self.items[n]['entry']

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
        keylist = content.keys()
        keylist.sort()
        for key in keylist:
            addr = "0x%.12X" % content[key].address
            size = "%d (0x%X)" % (content[key].size, content[key].size)
            comment = content[key].comment
            self.items.append({ 'mem_id': key, 'entry': [ addr, size, comment ] })

    def show(self, modal):
        # first item is alredy selected
        if len(self.items) != 0:
            self.linkList =  [ self.items[0]['mem_id'] ]
        return self.Show(modal) >= 0

__all__ = [
    'MemoryManagerView'
]
