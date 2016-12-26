#
#  ExecQueryDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form
from idaapi import textctrl_info_t

class ExecQueryDialog(Form):
    textFlags = textctrl_info_t.TXTF_AUTOINDENT|textctrl_info_t.TXTF_ACCEPTTABS|textctrl_info_t.TXTF_FIXEDFONT
    textTab = 4

    def __init__(self, db_list):
        Form.__init__(self, r"""STARTITEM {id:db_id}
BUTTON YES* Exec
BUTTON CANCEL Cancel
Execute Query

<##DB ID\::{db_id}>
<##Query\::{db_query}>
""", {
        'db_id': Form.DropdownListControl(
                        items=db_list,
                        readonly=True,
                        selval=0,
                        swidth=20,
                        width=20),
        'db_query': Form.MultiLineTextControl(flags=self.textFlags, tabsize=self.textTab, width=200, swidth=200),
        })

__all__ = [
	'ExecQueryDialog'
]
