// SPDX-License-Identifier: BSD-2-Clause
/*
 * Cpyright 2019 NXP
 *
 * Brief  Pseudo Trusted Application.
 *        DEK Blob encapsulation.
 */

#include <drivers/caam/crypto_extension.h>
#include <kernel/pseudo_ta.h>
#include <pta_dek_blob.h>
#include <string.h>
#include <tee_api_types.h>

#define PTA_NAME "dek_blob.pta"

/*
 * Generate HAB DEK blob for encrypted boot
 *
 * param_types    TEE parameters
 * params         Buffer parameters
 */
static TEE_Result generate_dek_blob_pta(uint32_t param_types,
					TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct hab_dek_blob_header *hdr = NULL;
	struct crypto_blob dek_blob = {};
	struct crypto_sm_page sm_page = {};
	bool backward_compatibility = false;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_MEMREF_OUTPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT);

	/* Keep backward compatibility with old API. */
	uint32_t old_exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
				TEE_PARAM_TYPE_MEMREF_OUTPUT,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types &&
	    param_types != old_exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the input payload length that must be 128/192/256 bits */
	if (params[0].memref.size != (128 / 8) &&
	    params[0].memref.size != (192 / 8) &&
	    params[0].memref.size != (256 / 8))
		return TEE_ERROR_BAD_PARAMETERS;

	/* Check that the output blob length is:
	 *  - length of the HAB DEK Blob Header
	 *  - length of the input payload + Blob Padding
	 */
	if (params[1].memref.size < sizeof(struct hab_dek_blob_header) +
					    params[0].memref.size +
					    BLOB_PAD_SIZE) {
		params[1].memref.size = sizeof(struct hab_dek_blob_header) +
					params[0].memref.size + BLOB_PAD_SIZE;
		return TEE_ERROR_SHORT_BUFFER;
	}

	dek_blob.payload.data = params[0].memref.buffer;
	dek_blob.payload.length = params[0].memref.size;
	dek_blob.blob.data = params[1].memref.buffer;
	dek_blob.blob.length = params[1].memref.size;
	if (param_types == exp_param_types) {
		sm_page.page = params[2].value.a;
		sm_page.nb_pages = params[2].value.b;
		sm_page.partition = params[3].value.a;
	} else {
		/* Default behavior is to use Page 2 from Partition 1 */
		sm_page.page = 2;
		sm_page.nb_pages = 1;
		sm_page.partition = 1;
		/* keep compatibility with imx_3.2.y based optee-os */
		backward_compatibility = true;
	}

	memset((void *)dek_blob.blob.data, 0x0, dek_blob.blob.length);

	/* Let the place to the HAB DEK blob header inot the output blob */
	dek_blob.blob.data += sizeof(struct hab_dek_blob_header);
	dek_blob.blob.length += sizeof(struct hab_dek_blob_header);

	/*
	 * Create the key modifier:
	 * 31                    16            8            0
	 * ---------------------------------------------------
	 * | Length of the payload | AES - 0x55 | CCM - 0x66 |
	 * ---------------------------------------------------
	 */
	dek_blob.key[0] = SHIFT_U32(dek_blob.payload.length & 0xFF, 16) |
			  SHIFT_U32(0x55, 8) | SHIFT_U32(0x66, 0);

	res = caam_blob_sm_encapsulate(&dek_blob, &sm_page);
	if (res != TEE_SUCCESS) {
		EMSG("DEK Blob Encapsulation 0x%08" PRIx32, res);
		goto out;
	}

	/* Build HAB DEK blob header */
	hdr = params[1].memref.buffer;

	hdr->tag = HAB_HDR_TAG;
	hdr->len_msb = 0x00;
	hdr->len_lsb = dek_blob.blob.length + sizeof(*hdr);
	hdr->par = HAB_HDR_V4;
	hdr->mode = HAB_HDR_MODE_CCM;
	hdr->alg = HAB_HDR_ALG_AES;
	hdr->size = dek_blob.payload.length;
	hdr->flg = 0x00;

	DMSG("DEK Blob size = %d", hdr->len_lsb);

	params[1].memref.size = hdr->len_lsb;
	dhex_dump(NULL, 0, TRACE_DEBUG, (void *)params[1].memref.buffer,
		  params[1].memref.size);
	res = TEE_SUCCESS;
out:
	if (backward_compatibility)
		res = caam_sm_free_partition(sm_page.partition);

	return res;
}

/*
 * Free a Secure Memory partition
 *
 * param_types    TEE parameters
 * params         Buffer parameters
 */
static TEE_Result dek_blob_free_partition(uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types =
		TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE,
				TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return caam_sm_free_partition(params[0].value.a);
}

/*
 * Called when a pseudo TA is invoked.
 *
 * sess_ctx       Session Identifier
 * cmd_id         Command ID
 * param_types    TEE parameters
 * params         Buffer parameters
 */
static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
					  uint32_t cmd_id, uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	switch (cmd_id) {
	case PTA_DEK_CMD_BLOB_ENCAPSULATE:
		return generate_dek_blob_pta(param_types, params);
	case PTA_DEK_CMD_FREE_PARTITION:
		return dek_blob_free_partition(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = PTA_DEK_BLOB_UUID, .name = PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
