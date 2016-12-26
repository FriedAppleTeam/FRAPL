#
#  AddMemoryRangeDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form

class AddMemoryRangeDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:mem_addr}
BUTTON YES* Add
BUTTON CANCEL Cancel
Add Memory Range
Specify start address and size of new memory range.
<##Address\::{mem_addr}> <##Size\::{mem_size}>
<##Comment\::{mem_cmnt}>
""", {
        'mem_addr': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'mem_size': Form.NumericInput(swidth=10, tp=Form.FT_DEC),
        'mem_cmnt': Form.StringInput(swidth=41)
        })

__all__ = [
	'AddMemoryRangeDialog'
]
