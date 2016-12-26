#
#  CreateDbDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t

class CreateDbDialog(Form):
    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:db_id}
BUTTON YES* Save
BUTTON CANCEL Cancel
Create New DB

<##DB ID\:  :{db_id}>
<##DB File\::{db_path}>
<##First Table Query\::{db_table}>
""", {
        'db_id': Form.StringInput(swidth=15),
        'db_path': Form.FileInput(save=True),
        'db_table': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        })

__all__ = [
	'CreateDbDialog'
]
