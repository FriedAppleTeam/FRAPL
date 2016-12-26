#
#  PopupMenus.py
#  FridaLink UI  
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

from idaapi import UI_Hooks
from idaapi import get_tform_type
from idaapi import attach_action_to_popup, action_handler_t, action_desc_t, register_action, unregister_action
from idaapi import AST_ENABLE_ALWAYS
from idaapi import BWN_IMPORTS, BWN_FUNCS, BWN_DISASM
from PyQt5 import QtGui, QtCore, QtWidgets

from .Actions import *

from ..Utils.Logging import fl_log as fl_log
import idautils

g_PopupMenuHook = None

class PopupHook(UI_Hooks):
    def __init__(self, instance):
        UI_Hooks.__init__(self)
        self.pluginInstance = instance

    def term(self):
        self.pluginInstance.term()

    def finish_populating_tform_popup(self, form, popup_handle):
        ALT = None
        if QtWidgets.QApplication.keyboardModifiers() == QtCore.Qt.AltModifier:
            ALT = True

        if get_tform_type(form) == BWN_IMPORTS:
            if ALT is not None:
                attach_action_to_popup(form, popup_handle, "fridalink:hook_imp_cpu", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_imp_stack", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_imp_backtrace", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_imp_linkmem", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "-", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_imp_edit", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:unhook_imp_symbol", "Frida Link/")
            else:
                attach_action_to_popup(form, popup_handle, "fridalink:hook_imp_symbol", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:replace_imp_symbol", "Frida Link/")
                attach_action_to_popup(form, popup_handle, "fridalink:load_imp_module", "Frida Link/")
        elif get_tform_type(form) == BWN_FUNCS:
            attach_action_to_popup(form, popup_handle, "-", "")
            attach_action_to_popup(form, popup_handle, "fridalink:hook_func_once", "Frida Link/")
            attach_action_to_popup(form, popup_handle, "fridalink:hook_func_perm", "Frida Link/")
            attach_action_to_popup(form, popup_handle, "fridalink:hook_func_cust", "Frida Link/")
            attach_action_to_popup(form, popup_handle, "fridalink:replace_func", "Frida Link/")
        elif get_tform_type(form) == BWN_DISASM:
            attach_action_to_popup(form, popup_handle, "",None)
            allowNewInstHook = False
            allowEditInstHook = False
            allowNewFuncHook = False
            allowEditFuncHook = False
            allowNewFuncReplace = False
            allowEditFuncReplace = False

            if self.pluginInstance.replacedFunction():
                allowEditFuncReplace = True
            else:
                if self.pluginInstance.hookedInstruction() == False:
                    allowNewInstHook = True
                    if self.pluginInstance.hookedFunction() == False:
                        allowNewFuncHook = True
                        allowNewFuncReplace = True
                    else:
                        allowEditFuncHook = True
                else:
                    allowEditInstHook = True
                    if self.pluginInstance.hookedFunction() == False:
                        allowNewFuncHook = True
                    else:
                        allowEditFuncHook = True

            if allowNewInstHook:
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_once", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_perm", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_brk_once", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_brk_perm", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_cust", "Frida Link/Instruction/")

            if allowEditInstHook:
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_cpu", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_stack", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_backtrace", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_linkmem", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "-", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_inst_edit", "Frida Link/Instruction/")
                attach_action_to_popup(form, popup_handle, "fridalink:unhook_inst", "Frida Link/Instruction/")

            if allowEditFuncHook:
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_cpu", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_stack", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_backtrace", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_linkmem", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "-", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_edit", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:unhook_func", "Frida Link/Function/")

            if allowNewFuncHook:                
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_once", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_perm", "Frida Link/Function/")
                attach_action_to_popup(form, popup_handle, "fridalink:hook_func_cust", "Frida Link/Function/")

            if allowNewFuncReplace:
                attach_action_to_popup(form, popup_handle, "fridalink:replace_func", "Frida Link/Function/")

            if allowEditFuncReplace:
                attach_action_to_popup(form, popup_handle, "fridalink:replace_func_edit", "Frida Link/Function/")                
                attach_action_to_popup(form, popup_handle, "fridalink:replace_func_del", "Frida Link/Function/")

            attach_action_to_popup(form, popup_handle, "fridalink:get_real_address", "Frida Link/")

        return 0

class IdaPopupMenuActionHandler(action_handler_t):
    def __init__(self, handler, action):
        action_handler_t.__init__(self)
        self.actionHandler = handler
        self.actionType = action
 
    def activate(self, ctx):
        CTRL = None
        modifiers = QtWidgets.QApplication.keyboardModifiers()
        if modifiers == QtCore.Qt.AltModifier:
            ALT = True
        elif modifiers == QtCore.Qt.ControlModifier:
            CTRL = True

        if ctx.form_type == BWN_DISASM:
            self.actionHandler.handleIdaViewMenuAction(self.actionType)
        elif ctx.form_type == BWN_IMPORTS:
            idx = ctx.chooser_selection.at(0)
            self.actionHandler.handleImportViewMenuAction(self.actionType, idx-1)
        elif ctx.form_type == BWN_FUNCS:
            idx = ctx.chooser_selection.at(0)
            self.actionHandler.handleFuncViewMenuAction(self.actionType, idx-1)
        return 1

    # This action is always available.
    def update(self, ctx):
        return AST_ENABLE_ALWAYS

def RegisterAction(act_name, act_text, act_handler, shortcut, tooltip, icon):
    newAction = action_desc_t(
        act_name,       # The action name. This acts like an ID and must be unique
        act_text,       # The action text.
        act_handler,    # The action handler.
        shortcut,       # Optional: the action shortcut
        tooltip,        # Optional: the action tooltip (available in menus/toolbar)
        icon)           # Optional: the action icon (shows when in menus/toolbars)
    register_action(newAction)

def RegisterMenuActions(handler):
    global g_PopupMenuHook
    # IDA View / Functions View
    RegisterAction('fridalink:hook_inst_once',      'Hook Once',                IdaPopupMenuActionHandler(handler, kPopupAction_HookInstOnce),          None,           'Hook instruction under cursor once.',         -1)
    RegisterAction('fridalink:hook_inst_perm',      'Hook Permanently',         IdaPopupMenuActionHandler(handler, kPopupAction_HookInstPerm),          None,           'Hook instruction under cursor permanently.',  -1)
    RegisterAction('fridalink:hook_inst_brk_once',  'Breakpoint Once',          IdaPopupMenuActionHandler(handler, kPopupAction_HookInstBreakOnce),     None,           'Break on instruction under cursor.',          -1)
    RegisterAction('fridalink:hook_inst_brk_perm',  'Breakpoint Permanently',   IdaPopupMenuActionHandler(handler, kPopupAction_HookInstBreakPerm),     None,           'Break on instruction under cursor.',          -1)
    RegisterAction('fridalink:hook_inst_cust',      'Hook Custom...',           IdaPopupMenuActionHandler(handler, kPopupAction_HookInstCust),          'SHIFT+CTRL+C', 'Hook instruction under cursor and customize.',-1)
    RegisterAction('fridalink:hook_func_once',      'Hook Once',                IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncOnce),          None,           'Hook function under cursor once.',            -1)
    RegisterAction('fridalink:hook_func_perm',      'Hook Permanently',         IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncPerm),          None,           'Hook function under cursor permanently.',     -1)
    RegisterAction('fridalink:hook_func_cust',      'Hook Custom...',           IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncCust),          'SHIFT+CTRL+F', 'Hook function under cursor and customize.',   -1)
    RegisterAction('fridalink:hook_inst_edit',      'Edit',                     IdaPopupMenuActionHandler(handler, kPopupAction_HookInstEdit),          None,           'Edit instruction hook.',                      -1)
    RegisterAction('fridalink:hook_func_edit',      'Edit',                     IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncEdit),          None,           'Edit function hook.',                         -1)
    RegisterAction('fridalink:hook_inst_cpu',       'Show Recent CPU Context',  IdaPopupMenuActionHandler(handler, kPopupAction_HookInstCPU),           None,           'Show CPU context for hook',                   -1)
    RegisterAction('fridalink:hook_func_cpu',       'Show Recent CPU Context',  IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncCPU),           None,           'Show CPU context for hook',                   -1)
    RegisterAction('fridalink:hook_inst_stack',     'Show Recent Stack',        IdaPopupMenuActionHandler(handler, kPopupAction_HookInstStack),         None,           'Show stack for hook',                         -1)
    RegisterAction('fridalink:hook_func_stack',     'Show Recent Stack',        IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncStack),         None,           'Show stack for hook',                         -1)
    RegisterAction('fridalink:hook_inst_backtrace', 'Show Recent Backtrace',    IdaPopupMenuActionHandler(handler, kPopupAction_HookInstBacktrace),     None,           'Show backtrace for hook',                     -1)
    RegisterAction('fridalink:hook_func_backtrace', 'Show Recent Backtrace',    IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncBacktrace),     None,           'Show backtrace for hook',                     -1)
    RegisterAction('fridalink:hook_inst_linkmem',   'Set Linked Memory',        IdaPopupMenuActionHandler(handler, kPopupAction_HookInstLinkMem),       None,           'Link memory region to hook',                  -1)
    RegisterAction('fridalink:hook_func_linkmem',   'Set Linked Memory',        IdaPopupMenuActionHandler(handler, kPopupAction_HookFuncLinkMem),       None,           'Link memory region to hook',                  -1)
    RegisterAction('fridalink:unhook_inst',         'Remove',                   IdaPopupMenuActionHandler(handler, kPopupAction_UnhookInst),            None,           'Unhook instruction.',                         -1)
    RegisterAction('fridalink:unhook_func',         'Remove',                   IdaPopupMenuActionHandler(handler, kPopupAction_UnhookFunc),            None,           'Unhook function.',                            -1)
    RegisterAction('fridalink:replace_func',        'Replace Implementation',   IdaPopupMenuActionHandler(handler, kPopupAction_ReplaceFunc),           None,           'Replace function under.',                     -1)
    RegisterAction('fridalink:replace_func_edit',   'Edit Implementation',      IdaPopupMenuActionHandler(handler, kPopupAction_ReplaceFuncEdit),       None,           'Replace function under.',                     -1)
    RegisterAction('fridalink:replace_func_del',    'Restore Implementation',   IdaPopupMenuActionHandler(handler, kPopupAction_ReplaceFuncDel),        None,           'Replace function under.',                     -1)
    RegisterAction('fridalink:get_real_address',    'Get Real Address',         IdaPopupMenuActionHandler(handler, kPopupAction_GetRealAddress),        None,           'Get real address.',                           -1)
    # Imports View
    RegisterAction('fridalink:hook_imp_symbol',     'Hook Symbol',              IdaPopupMenuActionHandler(handler, kPopupAction_HookImportSymbol),      None,           'Hook symbol...',                              -1)
    RegisterAction('fridalink:hook_imp_cpu',        'Show Recent CPU Context',  IdaPopupMenuActionHandler(handler, kPopupAction_HookImpSymbolCPU),      None,           'Show CPU context for hook',                   -1)
    RegisterAction('fridalink:hook_imp_stack',      'Show Recent Stack',        IdaPopupMenuActionHandler(handler, kPopupAction_HookImpSymbolStack),    None,           'Show stack for hook',                         -1)
    RegisterAction('fridalink:hook_imp_backtrace',  'Show Recent Backtrace',    IdaPopupMenuActionHandler(handler, kPopupAction_HookImpSymbolBacktrace),None,           'Show backtrace for hook',                     -1)
    RegisterAction('fridalink:hook_imp_linkmem',    'Set Linked Memory',        IdaPopupMenuActionHandler(handler, kPopupAction_HookImpSymbolLinkMem),  None,           'Link memory region to hook',                  -1)
    RegisterAction('fridalink:hook_imp_edit',       'Edit',                     IdaPopupMenuActionHandler(handler, kPopupAction_HookImpSymbolEdit),     None,           'Edit import hook',                            -1)
    RegisterAction('fridalink:unhook_imp_symbol',   'Remove',                   IdaPopupMenuActionHandler(handler, kPopupAction_UnhookImpSymbol),       None,           'Unhook symbol',                               -1)
    RegisterAction('fridalink:replace_imp_symbol',  'Replace Symbol',           IdaPopupMenuActionHandler(handler, kPopupAction_ReplaceImportSymbol),   None,           'Replace symbol...',                           -1)
    RegisterAction('fridalink:load_imp_module',     'Load Module',              IdaPopupMenuActionHandler(handler, kPopupAction_LoadImportModule),      None,           'Load Module...',                              -1)

    g_PopupMenuHook = PopupHook(handler)
    g_PopupMenuHook.hook()

def UnregisterMenuActions():
    global g_PopupMenuHook
    if g_PopupMenuHook != None:
        g_PopupMenuHook.unhook()

    # IDA View / Functions View
    unregister_action('fridalink:hook_inst_once')
    unregister_action('fridalink:hook_inst_perm')
    unregister_action('fridalink:hook_inst_brk_once')
    unregister_action('fridalink:hook_inst_brk_perm')
    unregister_action('fridalink:hook_inst_cust')
    unregister_action('fridalink:hook_func_once')
    unregister_action('fridalink:hook_func_perm')
    unregister_action('fridalink:hook_func_cust')
    unregister_action('fridalink:hook_inst_edit')
    unregister_action('fridalink:hook_func_edit')
    unregister_action('fridalink:hook_inst_cpu')
    unregister_action('fridalink:hook_func_cpu')
    unregister_action('fridalink:hook_inst_stack')
    unregister_action('fridalink:hook_func_stack')
    unregister_action('fridalink:hook_inst_backtrace')
    unregister_action('fridalink:hook_func_backtrace')
    unregister_action('fridalink:hook_inst_linkmem')
    unregister_action('fridalink:hook_func_linkmem')
    unregister_action('fridalink:unhook_inst')
    unregister_action('fridalink:unhook_func')
    unregister_action('fridalink:replace_func')
    unregister_action('fridalink:replace_func_edit')
    unregister_action('fridalink:replace_func_del')
    unregister_action('fridalink:get_real_address')
    # Imports View
    unregister_action('fridalink:hook_imp_symbol')
    unregister_action('fridalink:replace_imp_symbol')


__all__ = [
    'RegisterMenuActions',
    'UnregisterMenuActions'
]
