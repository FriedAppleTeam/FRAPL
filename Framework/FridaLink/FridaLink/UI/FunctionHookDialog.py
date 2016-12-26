#
#  FunctionHookDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t
from idc import AskFile

class FunctionHookDialog(Form):

    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self, module, address, symbol, recentOnEnter, recentOnLeave):
        Form.__init__(self, r"""STARTITEM {id:script_enter}
BUTTON YES* Save
BUTTON CANCEL Cancel
Function Hook

{segment}  {address}:  {symbol} 

<Once:{set_once}>
<Permanent:{set_perm}>{trigger}>

Recent onEnter script file:{src_file_enter}
<##onEnter script\::{script_enter}>
<##Load from file:{loadfile_enter}><##Update from file:{update_enter}>
Recent onLeave script file:{src_file_leave}
<##onLeave script\::{script_leave}>
<##Load from file:{loadfile_leave}><##Update from file:{update_leave}>
""", {
        'segment': Form.StringLabel("[" + module + "]", tp='F'),
        'address': Form.StringLabel(address, tp='A'),
        'symbol': Form.StringLabel(symbol, tp='X'),
        'trigger': Form.RadGroupControl(("set_once", "set_perm")),
        'src_file_enter': Form.StringLabel(recentOnEnter if recentOnEnter is not None else "", tp='f'),
        'script_enter': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        'loadfile_enter': Form.ButtonInput(self.onLoadEnter),
        'update_enter': Form.ButtonInput(self.onUpdateEnter),
        'src_file_leave': Form.StringLabel(recentOnLeave if recentOnLeave is not None else "", tp='f'),
        'script_leave': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        'loadfile_leave': Form.ButtonInput(self.onLoadLeave),
        'update_leave': Form.ButtonInput(self.onUpdateLeave),
        })
        self.recentScriptFileEnter = recentOnEnter
        self.recentScriptFileLeave = recentOnLeave

    def onLoadEnter(self, code=0):
        filePath = AskFile(0, "*.js", "Load Frida script")
        if filePath is None:
            return
        self.recentScriptFileEnter = filePath
        with open(self.recentScriptFileEnter, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.src_file_enter, filePath)
            self.SetControlValue(self.script_enter, text_info)
            file.close()

    def onUpdateEnter(self, code=0):
        if self.recentScriptFileEnter is None:
            return
        with open(self.recentScriptFileEnter, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.script_enter, text_info)
            file.close()

    def onLoadLeave(self, code=0):
        filePath = AskFile(0, "*.js", "Load Frida script")
        if filePath is None:
            return
        self.recentScriptFileLeave = filePath
        with open(self.recentScriptFileLeave, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.src_file_leave, filePath)
            self.SetControlValue(self.script_leave, text_info)
            file.close()

    def onUpdateLeave(self, code=0):
        if self.recentScriptFileLeave is None:
            return
        with open(self.recentScriptFileLeave, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.script_leave, text_info)
            file.close()

__all__ = [
    'FunctionHookDialog'
]
