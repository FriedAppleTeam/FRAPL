#
#  FunctionReplaceDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t
from idc import AskFile

class FunctionReplaceDialog(Form):

    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self, module, address, symbol, recent):
        Form.__init__(self, r"""STARTITEM {id:ret_type}
BUTTON YES* Save
BUTTON CANCEL Cancel
Function Implementation Replace

{segment}  {address}:  {symbol} 

<##return type\::{ret_type}>   <##arguments\::{args}>

{orig_call}
Recent source file:{src_file}
<##Script source code\::{script}>
<##Load from file:{loadfile}><##Update from file:{update}>
""", {
        'segment': Form.StringLabel("[" + module + "]", tp='F'),
        'address': Form.StringLabel(address, tp='A'),
        'symbol': Form.StringLabel(symbol, tp='X'),
        'ret_type': Form.StringInput(swidth=10),
        'args': Form.StringInput(swidth=40),
        'orig_call': Form.StringLabel("NOTE: Original implementation can be called using `frlOriginalImpl()`"),        
        'src_file': Form.StringLabel(recent if recent is not None else "", tp='f'),
        'script': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        'loadfile': Form.ButtonInput(self.onLoadScript),
        'update': Form.ButtonInput(self.onUpdateScript),
        })
        self.recentScriptFile = recent

    def onLoadScript(self, code=0):
        filePath = AskFile(0, "*.js", "Load Frida script")
        if filePath is None:
            return
        self.recentScriptFile = filePath
        with open(self.recentScriptFile, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.src_file, filePath)
            self.SetControlValue(self.script, text_info)
            file.close()

    def onUpdateScript(self, code=0):
        if self.recentScriptFile is None:
            return
        with open(self.recentScriptFile, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.script, text_info)
            file.close()

__all__ = [
    'FunctionReplaceDialog'
]