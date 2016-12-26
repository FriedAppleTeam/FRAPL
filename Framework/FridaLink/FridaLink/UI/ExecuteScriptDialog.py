#
#  ExecuteScriptDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t
from idc import AskFile

class ExecuteScriptDialog(Form):
    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self, engine, recentFile):
        Form.__init__(self, r"""STARTITEM {id:script}
BUTTON YES* Save
BUTTON CANCEL Close
Execute Custom Frida Script

Recent source file:{src_file}
<##Script source code\::{script}>
<##Load from file:{loadfile}><##Update from file:{update}><##Execute:{execute}>
""", {
        'src_file': Form.StringLabel(recentFile if recentFile is not None else "", tp='f'),
        'script': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        'loadfile': Form.ButtonInput(self.onLoad),
        'update': Form.ButtonInput(self.onUpdate),
        'execute': Form.ButtonInput(self.onExecute),
        })
        self.engine = engine
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

    def onExecute(self, code=0):
        script = self.GetControlValue(self.script).text
        self.engine.executeScript(script)

__all__ = [
    'ExecuteScriptDialog'
]
