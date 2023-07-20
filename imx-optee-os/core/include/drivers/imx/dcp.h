/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __IMX_DCP_H__
#define __IMX_DCP_H__

#include <compiler.h>
#include <tee_api_types.h>
#include <types_ext.h>
#include <util.h>

#define DCP_SHA_BLOCK_SIZE     64
#define DCP_AES_BLOCK_SIZE     64
#define DCP_AES128_KEY_SIZE    16
#define DCP_AES128_IV_SIZE     16
#define DCP_AES128_BUFFER_SIZE 16

enum dcp_key_mode {
	SRAM0 = 0,
	SRAM1,
	SRAM2,
	SRAM3,
	PAYLOAD,
	OTP,
};

enum dcp_aes_mode {
	ECB,
	CBC,
};

enum dcp_aes_op {
	ENCRYPT,
	DECRYPT,
};

enum dcp_hash_config {
	DCP_SHA1,
	DCP_SHA256,
	DCP_CRC32,
	DCP_SHA_CHECK,
	DCP_SHA_NOCHECK,
};

enum dcp_channel {
	DCP_CHANN0 = 0,
	DCP_CHANN1,
	DCP_CHANN2,
	DCP_CHANN3,
	DCP_NB_CHANNELS,
	DCP_CHANN_ANY, /* Channel will be selected by software */
};

enum dcp_context_operation {
	DCP_SAVE_CONTEXT,
	DCP_RESTORE_CONTEXT,
};

struct dcp_descriptor {
	uint32_t next;
	uint32_t ctrl0;
	uint32_t ctrl1;
	void *src_buffer;
	void *dest_buffer;
	uint32_t buff_size;
	void *payload;
	uint32_t status;
};

struct dcp_align_buf {
	uint8_t *data;
	paddr_t paddr;
	size_t size;
};

struct dcp_data {
	struct dcp_descriptor desc;
	enum dcp_channel channel;
	struct dcp_align_buf sw_context_buffer;
};

struct dcp_op_state {
	bool init;
	bool any_channel;
};

struct dcp_hashdata {
	struct dcp_data dcp_data;
	struct dcp_op_state op_state;
	enum dcp_hash_config hash_id;
	enum dcp_hash_config hash_check;
	uint8_t *check_value;
	uint8_t block_data[DCP_SHA_BLOCK_SIZE];
	size_t block_data_filled;
	size_t block_data_size;
	paddr_t paddr_block_data;
};

struct dcp_hashalg {
	unsigned int type;
	unsigned int size;
};

struct dcp_aesdata {
	struct dcp_data dcp_data;
	struct dcp_op_state op_state;
	uint8_t buffer[DCP_AES128_IV_SIZE + DCP_AES128_KEY_SIZE];
	unsigned int payload_size;
};

struct dcp_cipher_init {
	enum dcp_aes_op op;
	enum dcp_aes_mode mode;
	enum dcp_key_mode key_mode;
	enum dcp_channel channel;
	/* Key if key_mode is PAYLOAD */
	uint8_t *key;
	uint8_t *iv;
};

/*
 * Store key in the SRAM
 *
 * @key    Buffer containing the key to store (128 bit)
 * @index  Index of the key (0, 1, 2 or 3)
 */
TEE_Result dcp_store_key(uint32_t *key, unsigned int index);

/*
 * Initialize AES-128 operation
 *
 * @aes    AES operation context
 * @init   Data for aesdata initialization
 */
TEE_Result dcp_aes_do_init(struct dcp_aesdata *aes,
			   struct dcp_cipher_init *init);

/*
 * Update AES-128 operation
 *
 * @aes   AES operation context
 * @src   Source data to encrypt/decrypt
 * @dst   [out] Destination buffer
 * size   Size of source data in bytes, must be 16 bytes multiple
 */
TEE_Result dcp_aes_do_update(struct dcp_aesdata *aes, const uint8_t *src,
			     uint8_t *dst, size_t size);

/*
 * Finalize AES-128 operation
 *
 * @aes   AES operation context
 */
void dcp_aes_do_final(struct dcp_aesdata *aes);

/*
 * Initialize hash operation
 *
 * @hashdata   Hash operation context
 */
TEE_Result dcp_sha_do_init(struct dcp_hashdata *hashdata);

/*
 * Update hash operation
 *
 * @hashdata   Hash operation context
 * @data       Buffer to hash
 * @len        Size of the input buffer in bytes
 */
TEE_Result dcp_sha_do_update(struct dcp_hashdata *hashdata, const uint8_t *data,
			     size_t len);

/*
 * Finalize the hash operation
 *
 * @hashdata      Hash operation context
 * @digest        [out] Result of the hash operation
 * @digest_size   Digest buffer size in bytes
 */
TEE_Result dcp_sha_do_final(struct dcp_hashdata *hashdata, uint8_t *digest,
			    size_t digest_size);

/*
 * AES128-CMAC algorithm
 * Message is composed of:
 *	Counter: Here 1 iteration to derive 128 bits
 *	Label: a string that identified the purpose for the derived keying
 *	       material
 *	0: Label null termination
 *	Context: a string containing the information related to the derived
 *		 keying material
 *	L: length of the derived key represented as one byte = 128
 *
 * @message       Message used in the algorithm
 * @message_size  Size of the message in bytes, up to 16 bytes
 * @output        [out] Result of the operation
 * @init          Data for aesdata initialization
 */
TEE_Result dcp_aes_cmac(uint8_t *message, size_t message_size, uint8_t *output,
			struct dcp_cipher_init *init);

/* Initialize DCP */
TEE_Result dcp_init(void);

#ifndef CFG_DT
static inline TEE_Result dcp_vbase(vaddr_t *base __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}
#endif /* CFG_DT */

#endif /* __IMX_DCP_H__ */
