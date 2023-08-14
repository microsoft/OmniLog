// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022, Sarbartha Banerjee
 */

/*
 * This pseudo TA is used by normal world kernel driver to store omnilog 
 * from the buffer to the storage (sdcard).
 */

#include <config.h>
#include <kernel/early_ta.h>
#include <kernel/linker.h>
#include <kernel/pseudo_ta.h>
#include <kernel/tee_ta_manager.h>
#include <pta_storage_call.h>
#include <string.h>
#include <user_ta_header.h>
#include <sm/optee_smc.h>
#include <kernel/thread_defs.h>
#include <kernel/thread.h>
#include <smccc.h>
#include <sm/sm.h>

struct log_entry { 
	uint64_t log;
};
char *buffer;
static TEE_Result config_buf(uint32_t param_types, 
									TEE_Param params[TEE_NUM_PARAMS])
{

	// Params accepted are base address of the log buffer and log size
	uint32_t types = TEE_PARAM_TYPES( 	TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE
										);
	uint64_t size = params[0].value.a;

	if (types!= param_types)
		return TEE_ERROR_BAD_PARAMETERS;
	
	// --- Allocate a secure buffer with address and size sent by kernel module
	buffer = malloc(size* sizeof(char));

	//DMSG("Buffer size is %ld",size);
	// --- SMC Call to omnilog_config_handler
	thread_smc(0xC2000010, buffer, size, 0);
	
	return TEE_SUCCESS;
}
static TEE_Result query_buf_status(uint32_t param_types, 
									TEE_Param params[TEE_NUM_PARAMS])
{
	// Params accepted are base address of the log buffer and log size
	uint32_t types = TEE_PARAM_TYPES( 	TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_VALUE_OUTPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE
										);
	if (types!= param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	uint64_t buf_id = params[0].value.a;

	// Return savereq to the kernel
	
	return TEE_SUCCESS;
}

static TEE_Result dump_buf_to_storage(uint32_t param_types, 
									TEE_Param params[TEE_NUM_PARAMS])
{

	// Params accepted are base address of the log buffer and log size
	uint32_t types = TEE_PARAM_TYPES( 	TEE_PARAM_TYPE_VALUE_INPUT,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE,
										TEE_PARAM_TYPE_NONE
										);
	uint64_t buf_id = params[0].value.a;
	//DMSG("[PTA]: Buffer id is %d",buf_id);

	if (types!= param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	thread_smc(0xC2000012, buf_id, 0, 0);
	return TEE_SUCCESS;
}

							  


static TEE_Result invoke_command(void *sess_ctx __unused, uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	//DMSG("The cmd_id selected is %d",cmd_id);
	switch (cmd_id) {
	case PTA_STORAGE_CALL_CONFIG_BUFFER:
		return config_buf(param_types,params);
		break;
	case PTA_STORAGE_CALL_RET_BUF_STATUS:
		return query_buf_status(param_types, params);
		break;
	case PTA_STORAGE_CALL_DUMP:
		return dump_buf_to_storage(param_types, params);
		break;
	default:
		break;
	}
	return TEE_ERROR_NOT_IMPLEMENTED;
}



pseudo_ta_register(.uuid = PTA_STORAGE_CALL_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);

