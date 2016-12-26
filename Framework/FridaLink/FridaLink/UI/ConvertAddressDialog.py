#
#  ConvertAddressDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form

class ConvertAddressDialog(Form):

    def __init__(self, engine, modules):
        Form.__init__(self, r"""STARTITEM {id:address}
BUTTON YES* OK
BUTTON CANCEL Cancel
Convert real address to IDB offset

{FormChangeCb}
<Module\: :{module}>
<##Real address\::{address}>
Module base: {mod_base}
<##IDB address\: :{idb_addr}>
""", {
        'module': Form.DropdownListControl(
                        items=modules,
                        readonly=True,
                        selval=0,
                        swidth=20,
                        width=20),
        'address': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'mod_base': Form.StringLabel("0x0", tp='A'),
        'idb_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'FormChangeCb': Form.FormChangeCb(self.OnFormChange)
        })
        self.engine = engine

    def OnFormChange(self, fid):
        if fid == self.module.id:
            mod_idx = self.GetControlValue(self.module)
            address = self.GetControlValue(self.address)
            base = self.engine.getModuleBase(mod_idx)
            loc_base = self.engine.getIdbModuleBase(self.engine.getModuleName(mod_idx))
            self.SetControlValue(self.mod_base, "0x%X" % base)
            self.SetControlValue(self.idb_addr, address - base + loc_base)
        elif fid == self.address.id:
            mod_idx = self.GetControlValue(self.module)
            address = self.GetControlValue(self.address)
            base = self.engine.getModuleBase(mod_idx)
            loc_base = self.engine.getIdbModuleBase(self.engine.getModuleName(mod_idx))
            self.SetControlValue(self.mod_base, "0x%X" % base)
            self.SetControlValue(self.idb_addr, address - base + loc_base)

__all__ = [
    'ConvertAddressDialog'
]
