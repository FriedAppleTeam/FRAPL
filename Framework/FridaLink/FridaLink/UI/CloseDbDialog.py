#
#  CloseDbDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form

class CloseDbDialog(Form):

    def __init__(self, db_list):
        Form.__init__(self, r"""STARTITEM {id:db_id}
BUTTON YES* Close
BUTTON CANCEL Cancel
Close DB

<##DB ID\::{db_id}>
""", {
        'db_id': Form.DropdownListControl(
                        items=db_list,
                        readonly=True,
                        selval=0,
                        swidth=20,
                        width=20),
        })

__all__ = [
	'CloseDbDialog'
]
