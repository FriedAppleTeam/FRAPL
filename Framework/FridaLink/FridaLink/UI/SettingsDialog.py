#
#  SettingsDialog.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import Form

class SettingsDialog(Form):
    def __init__(self):
        Form.__init__(self, r"""STARTITEM {id:host}
BUTTON YES* Save
BUTTON CANCEL Cancel
FridaLink Settings

<##Host\::{host}> <##Port\::{port}>

<##CPU context columns\::{cpuctx_cols}>
""", {
        'host': Form.StringInput(swidth=15),
        'port': Form.NumericInput(swidth=5, tp=Form.FT_DEC),
        'cpuctx_cols': Form.NumericInput(swidth=5, tp=Form.FT_DEC)
        })

__all__ = [
	'SettingsDialog'
]
