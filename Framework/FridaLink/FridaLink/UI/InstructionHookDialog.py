#
#  InstructionHookDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t
from idc import AskFile

class InstructionHookDialog(Form):

    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self, module, address, mnemonic, recentFile):
        Form.__init__(self, r"""STARTITEM {id:script}
BUTTON YES* Save
BUTTON CANCEL Cancel
Instruction Hook

{segment}  {address}:  {mnemonic} 

<Once:{set_once}>
<Permanent:{set_perm}>{trigger}>

Recent source file:{src_file}
<##Script source code\::{script}>
<##Load from file:{loadfile}><##Update from file:{update}>
""", {
        'segment': Form.StringLabel("[" + module + "]", tp='F'),
        'address': Form.StringLabel(address, tp='A'),
        'mnemonic': Form.StringLabel(mnemonic, tp='X'),
        'trigger': Form.RadGroupControl(("set_once", "set_perm")),
        'src_file': Form.StringLabel(recentFile if recentFile is not None else "", tp='f'),
        'script': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        'loadfile': Form.ButtonInput(self.onLoad),
        'update': Form.ButtonInput(self.onUpdate),
        })
        self.recentScriptFile = recentFile

    def onLoad(self, code=0):
        filePath = AskFile(0, "*.js", "Load Frida script")
        if filePath is None:
            return
        self.recentScriptFile = filePath
        with open(self.recentScriptFile, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.src_file, filePath)
            self.SetControlValue(self.script, text_info)
            file.close()

    def onUpdate(self, code=0):
        if self.recentScriptFile is None:
            return
        with open(self.recentScriptFile, 'r') as file:
            text_info = textctrl_info_t(text=file.read(), flags=self.textFlags, tabsize=self.textTab)
            self.SetControlValue(self.script, text_info)
            file.close()

__all__ = [
    'InstructionHookDialog'
]
