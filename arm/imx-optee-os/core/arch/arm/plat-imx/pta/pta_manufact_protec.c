// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Pseudo Trusted Application.
 *         Manufacturing Protection functionality.
 */
#include <drivers/caam/crypto_extension.h>
#include <kernel/pseudo_ta.h>
#include <pta_manufact_protec.h>
#include <string.h>
#include <tee_api_types.h>

#define PTA_NAME "manufact_protec.pta"

/*
 * Get the Manufacturing Protectuion Public key into parameter #0.
 *
 * @param_types    TEE parameter types
 * @params         TEE parameters
 */
static TEE_Result mp_get_public_key(uint32_t param_types,
				    TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct cryptobuf pubkey = {};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	pubkey.data = params[0].memref.buffer;
	pubkey.length = params[0].memref.size;

	/* mppub generation */
	res = crypto_mp_export_publickey(&pubkey);
	if (res != TEE_SUCCESS)
		EMSG("mppub_gen failed with code 0x%" PRIx32, res);

	params[0].memref.size = pubkey.length;
	return res;
}

/*
 * Manufacturing Proctection signature of the input buffer in parameter #0.
 * Return the signature into parameter #1
 * Return the additional signature identifier (MPMR) into parameter #2
 *
 * @param_types    TEE parameter types
 * @params         TEE parameters
 */
static TEE_Result mp_signature(uint32_t param_types,
			       TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct cryptobuf mpmr = {};
	struct crypto_mp_sign sdata = {};
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("MPSign function\n");

	/* MP Signature */
	sdata.message.data = (uint8_t *)params[0].memref.buffer;
	sdata.message.length = params[0].memref.size;

	sdata.signature.data = (uint8_t *)params[1].memref.buffer;
	sdata.signature.length = params[1].memref.size;

	memset(sdata.signature.data, 0, sdata.signature.length);

	res = crypto_mp_sign(&sdata);

	params[1].memref.size = sdata.signature.length;
	if (res != TEE_SUCCESS) {
		EMSG("Manufacturing Protection signature failed 0x%" PRIx32,
		     res);
		return res;
	}

	/* Get the addtionnal signature identifier (MPMR) */
	mpmr.data = params[2].memref.buffer;
	mpmr.length = params[2].memref.size;

	res = crypto_mp_export_mpmr(&mpmr);
	params[2].memref.size = mpmr.length;
	if (res != TEE_SUCCESS)
		EMSG("Manufacturing Protection export MPRM failed 0x%" PRIx32,
		     res);

	return res;
}

/*
 * Pseudo TA open session. Checks if TA is initiator.
 */
static TEE_Result
pta_mp_open_session(uint32_t param_types __unused,
		    TEE_Param pParams[TEE_NUM_PARAMS] __unused,
		    void **sess_ctx __unused)
{
	struct tee_ta_session *s = tee_ta_get_calling_session();

	if (!s)
		return TEE_ERROR_ACCESS_DENIED;

	return TEE_SUCCESS;
}

/*
 * Pseudo TA entry point
 *
 * @sess_ctx       Session Identifier
 * @cmd_id         Command ID
 * @param_types    TEE parameter types
 * @params         TEE parameters
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
					  uint32_t cmd_id, uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_MP_CMD_SIGNATURE_MPMR:
		return mp_signature(param_types, params);
	case PTA_MP_CMD_GET_PUBLIC_KEY:
		return mp_get_public_key(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_MANUFACT_PROTEC_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = pta_mp_open_session,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
