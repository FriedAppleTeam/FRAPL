#
#  MessageTypes.py
#  FridaLink Common
#
#  Created by Alexander Hude on 28/03/16.
#  Copyright (c) 2016 FriedApple. All rights reserved.
#

kFridaLink_ExecuteScript  		= "frl_exec_script"		# Execute custom script (IDA -> FRAPL)
kFridaLink_TargetInfo			= "frl_target_info"		# Request information about target (IDA <- FRAPL)
kFridaLink_ModulesRequest  		= "frl_modules_req"		# Request list of all modules (IDA -> FRAPL)
kFridaLink_ModulesResponse 		= "frl_modules_resp"	# Request list of all modules (IDA <- FRAPL)
kFridaLink_SetHookRequest  		= "frl_sethook_req"		# Hook instruction or function (IDA -> FRAPL)
kFridaLink_DelHookRequest		= "frl_delhook_req"		# Unhook instruction or function (IDA -> FRAPL)
kFridaLink_UpdHookRequest		= "frl_updhook_req"		# Update hook for instruction or function (IDA -> FRAPL)
kFridaLink_SetReplaceRequest  	= "frl_setrepl_req"		# Replace function (IDA -> FRAPL)
kFridaLink_DelReplaceRequest	= "frl_delrepl_req"		# Restore function (IDA -> FRAPL)
kFridaLink_UpdReplaceRequest	= "frl_updrepl_req"		# Update replaced function (IDA -> FRAPL)
kFridaLink_AddMemRequest		= "frl_addmem_req"		# Start monitoring memory range (IDA -> FRAPL)
kFridaLink_DelMemRequest		= "frl_delmem_req"		# Stop monitoring memory range (IDA -> FRAPL)
kFridaLink_FetchMemRequest		= "frl_fetchmem_req"	# Request memory region content (IDA -> FRAPL)
kFridaLink_FetchMemResponse		= "frl_fetchmem_resp"	# Response with memory region content (IDA <- FRAPL)
kFridaLink_Ack    	  	  		= "frl_ack"				# Acknowledgment packet (IDA -> FRAPL)
kFridaLink_ProcessBacktrace 	= "frl_bktrc_proc"		# Request backtrace processing from IDA (IDA <- FRAPL)
kFridaLink_HookResponse 		= "frl_hook_resp"		# Response on instruction or function hook (IDA <- FRAPL)
kFridaLink_ReplaceResponse 		= "frl_replace_resp"	# Response on function replace (IDA <- FRAPL)
kFridaLink_FraplLogEntry		= "frl_frapl_log"		# Add FRAPL log entry (IDA <- FRAPL)
kFridaLink_TargetLogEntry		= "frl_target_log"		# Add target log entry (IDA <- FRAPL)
kFridaLink_DBQuery				= "frl_db_query"		# Execute DB query
kFridaLink_DebugContinue		= "frl_debug_cont"		# Breakpoint continue execution
