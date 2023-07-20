// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <drivers/imx/dcp.h>
#include <kernel/tee_common_otp.h>
#include <local.h>
#include <trace.h>

#define HUK_MESSAGE_NULL_BYTE 0
#define NB_ITERATION_HUK      1
#define HUK_SIZE_BITS	      128

/* State of the generated HUK */
enum dcp_huk_state {
	DCP_HUK_EMPTY = 0,
	DCP_HUK_GENERATED,
	DCP_HUK_ERROR,
};

/* Information about HUK */
static struct {
	enum dcp_huk_state state;
	uint8_t data[HW_UNIQUE_KEY_LENGTH];
} dcp_huk = { .state = DCP_HUK_EMPTY };

/*
 * Generate Hardware Unique Key using the Data Co-Processor (DCP) AES128-CMAC
 * cryptographic operation
 * Follow dcp_aes_cmac message format
 *
 * @hwkey   [out] Hardware Unique Key private data
 * @chann   DCP channel to use for AES operation
 */
static TEE_Result dcp_generate_huk(struct tee_hw_unique_key *hwkey,
				   enum dcp_channel chann)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dcp_cipher_init init = {};
	const uint8_t content[DCP_AES128_BUFFER_SIZE] = { NB_ITERATION_HUK,
							  'h',
							  'u',
							  'k',
							  HUK_MESSAGE_NULL_BYTE,
							  'o',
							  'p',
							  't',
							  'e',
							  'e',
							  'o',
							  's',
							  'd',
							  'c',
							  'p',
							  HUK_SIZE_BITS };

	init.channel = chann;
	init.op = ENCRYPT;
	init.mode = ECB;
	init.key_mode = OTP;

	ret = dcp_aes_cmac((uint8_t *)content, DCP_AES128_BUFFER_SIZE,
			   hwkey->data, &init);
	if (ret != TEE_SUCCESS)
		EMSG("huk generation failed. Err = 0x%" PRIx32, ret);

	return ret;
}

/* HUK Generation perform on OPTEE OS boot */
TEE_Result tee_otp_get_hw_unique_key(struct tee_hw_unique_key *hwkey)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t size = HW_UNIQUE_KEY_LENGTH;

	if (!hwkey) {
		EMSG("HUK generation failed, hwkey structure is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!hwkey->data) {
		EMSG("HUK generation failed, hwkey->data buffer is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (size != DCP_AES128_KEY_SIZE) {
		EMSG("HW_UNIQUE_KEY_LENGTH is not 16 bytes");
		return TEE_ERROR_NOT_SUPPORTED;
	}

	ret = dcp_init();
	if (ret != TEE_SUCCESS) {
		EMSG("dcp_init failed");
		return ret;
	}

	if (dcp_huk.state == DCP_HUK_EMPTY) {
		/* HUK generation */
		ret = dcp_generate_huk(hwkey, DCP_CHANN_ANY);
		if (ret != TEE_SUCCESS) {
			dcp_huk.state = DCP_HUK_ERROR;
			EMSG("DCP HUK generation failed");
		} else {
			memcpy(dcp_huk.data, hwkey->data, HW_UNIQUE_KEY_LENGTH);
			dcp_huk.state = DCP_HUK_GENERATED;
			DMSG("DCP HUK generation ok");
		}
	} else if (dcp_huk.state == DCP_HUK_GENERATED) {
		/* Copy HUK's bakcup to destination buffer */
		memcpy(hwkey->data, dcp_huk.data, HW_UNIQUE_KEY_LENGTH);
		ret = TEE_SUCCESS;
		DMSG("HUK already generated");
	} else {
		/* DCP HUK can't be generated */
		EMSG("DCP HUK generation failed");
		ret = TEE_ERROR_GENERIC;
	}

	return ret;
}
