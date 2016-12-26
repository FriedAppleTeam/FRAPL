#
#  ArbitraryHookDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t
from idc import AskFile

class ArbitraryHookDialog(Form):

    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self, modules, recentOnEnter, recentOnLeave):
        Form.__init__(self, r"""STARTITEM {id:module}
BUTTON YES* Save
BUTTON CANCEL Cancel
Arbitrary Hook

                        !!! MAKE SURE YOU KNOW WHAT YOU ARE DOING HERE !!!

<Module\: :{module}> <##Address\::{address}>
<##Comment\::{comment}>

<Instruction:{set_inst}><Function:{set_func}>{hook_type}><Once:{set_once}><Permanent:{set_perm}>{trigger}>

Recent onEnter script file:{src_file_enter}
<##onEnter script\::{script_enter}>
<##Load from file:{loadfile_enter}><##Update from file:{update_enter}>
Recent onLeave script file:{src_file_leave}
<##onLeave script\::{script_leave}>
<##Load from file:{loadfile_leave}><##Update from file:{update_leave}>
""", {
        'module': Form.DropdownListControl(
                        items=modules,
                        readonly=True,
                        selval=0,
                        swidth=20,
                        width=20),
        'address': Form.NumericInput(swidth=20, tp=Form.FT_HEX),
        'comment': Form.StringInput(swidth=60),
        'hook_type': Form.RadGroupControl(("set_inst", "set_func"), secondary=False),
        'trigger': Form.RadGroupControl(("set_once", "set_perm"), secondary=True),
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
    'ArbitraryHookDialog'
]
