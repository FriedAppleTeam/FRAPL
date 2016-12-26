#
#  LoadModuleDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form

class LoadModuleDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:filePath}
BUTTON YES* Load
BUTTON CANCEL Cancel
Load Module
Choose module binary to be added to IDA database.
Note that depends on module size this may take a while.
<#Select a file to open#:{filePath}>
""", {
        'filePath': Form.FileInput(swidth=50, open=True),
        })

__all__ = [
	'LoadModuleDialog'
]
