// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */

#include <config.h>
#include <dcp_utils.h>
#include <drivers/imx/dcp.h>
#include <imx-regs.h>
#include <io.h>
#include <kernel/mutex.h>
#include <kernel/spinlock.h>
#ifdef CFG_DT
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <libfdt.h>
#endif
#include <local.h>
#include <mm/core_memprot.h>
#include <tee/cache.h>
#include <utee_defines.h>

static vaddr_t dcp_base;
static bool driver_init;
static unsigned int clk_refcount;
static unsigned int key_store_spinlock = SPINLOCK_UNLOCK;
static unsigned int clock_spinlock = SPINLOCK_UNLOCK;
static struct dcp_align_buf hw_context_buffer;

static struct mutex lock_channel[DCP_NB_CHANNELS] = {
	[DCP_CHANN0] = MUTEX_INITIALIZER,
	[DCP_CHANN1] = MUTEX_INITIALIZER,
	[DCP_CHANN2] = MUTEX_INITIALIZER,
	[DCP_CHANN3] = MUTEX_INITIALIZER,
};

static const struct dcp_hashalg hash_alg[3] = {
	[DCP_SHA1] = {
		.type = DCP_CONTROL1_HASH_SELECT_SHA1,
		.size = TEE_SHA1_HASH_SIZE,
	},
	[DCP_SHA256] = {
		.type = DCP_CONTROL1_HASH_SELECT_SHA256,
		.size = TEE_SHA256_HASH_SIZE,
	},
	[DCP_CRC32] = {
		.type = DCP_CONTROL1_HASH_SELECT_CRC32,
		.size = DCP_CRC32_SIZE,
	},
};

/*
 * Enable/disable DCP clock.
 *
 * @enable   Enable the clock if true, disable if false.
 */
static void dcp_clk_enable(bool enable)
{
	vaddr_t ccm_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	uint32_t clock_except = cpu_spin_lock_xsave(&clock_spinlock);

	if (enable) {
		if (clk_refcount++ > 0)
			goto out;
		else
			io_setbits32(ccm_base + CCM_CCGR0, DCP_CLK_ENABLE_MASK);
	} else {
		if (clk_refcount == 0)
			goto out;
		else if (--clk_refcount > 0)
			goto out;
		else
			io_clrbits32(ccm_base + CCM_CCGR0, DCP_CLK_ENABLE_MASK);
	}
out:
	cpu_spin_unlock_xrestore(&clock_spinlock, clock_except);
}

/*
 * Lock the given channel with a mutex.
 *
 * @chan   DCP channel to lock
 */
static TEE_Result dcp_lock_known_channel(enum dcp_channel chan)
{
	if (mutex_trylock(&lock_channel[chan]))
		return TEE_SUCCESS;
	else
		return TEE_ERROR_BUSY;
}

/*
 * Unlock the given channel.
 *
 * @chan   DCP channel to unlock
 */
static void dcp_unlock_channel(enum dcp_channel chan)
{
	if (lock_channel[chan].state)
		mutex_unlock(&lock_channel[chan]);
}

/*
 * Try to find an unlocked channel and lock it.
 *
 * @channel   [out] Channel locked if the function returns TEE_SUCCESS
 */
static TEE_Result dcp_lock_any_ready_channel(enum dcp_channel *channel)
{
	TEE_Result ret = TEE_ERROR_BUSY;
	enum dcp_channel chan = DCP_CHANN0;

	for (chan = 0; chan < DCP_NB_CHANNELS; chan++) {
		ret = dcp_lock_known_channel((enum dcp_channel)chan);
		if (ret == TEE_SUCCESS) {
			*channel = (enum dcp_channel)chan;
			return ret;
		}
	}

	EMSG("All channels are busy");

	return ret;
}

/*
 * Lock a channel calling dcp_lock_any_ready_channel or dcp_lock_chosen_channel.
 *
 * @op_state   Information about the use of DCP_CHAN_ANY
 * @channel    Pointer on operation channel parameter
 */
static TEE_Result dcp_lock_channel(struct dcp_op_state *op_state,
				   enum dcp_channel *channel)
{
	if (op_state->any_channel)
		return dcp_lock_any_ready_channel(channel);
	else
		return dcp_lock_known_channel(*channel);
}

/*
 * Configure two descriptors to restore context before the operation and
 * save the context after, both done by dcp memory copy feature.
 *
 * @save_context_desc      [out] Save context descriptor
 * @restore_context_desc   [out] Restore context descriptor
 * @dcp_data		   Structure containing channel to use, dcp_descriptor
 *			   of the operation(HASH, AES) and pointer to the
 *			   sw context buffer
 */
static void dcp_context_switch_desc(struct dcp_descriptor *save_context_desc,
				    struct dcp_descriptor *restore_context_desc,
				    struct dcp_data *dcp_data)
{
	unsigned int offset = DCP_CONTEXT_SW_OFFSET(dcp_data->channel);

	/* Configure restore context descriptor */
	restore_context_desc->ctrl0 = DCP_CONTROL0_ENABLE_MEMCOPY |
				      DCP_CONTROL0_DECR_SEMAPHORE |
				      DCP_CONTROL0_CHAIN |
				      DCP_CONTROL0_INTERRUPT_ENABLE;
	restore_context_desc->ctrl1 = 0;
	restore_context_desc->payload = NULL;
	restore_context_desc->status = 0;
	restore_context_desc->buff_size = DCP_CONTEXT_CHANNEL_SIZE;
	restore_context_desc->src_buffer = dcp_data->sw_context_buffer.data;
	restore_context_desc->dest_buffer = hw_context_buffer.data + offset;
	restore_context_desc->next = virt_to_phys(&dcp_data->desc);

	/* Configure save context descriptor */
	save_context_desc->ctrl0 = DCP_CONTROL0_ENABLE_MEMCOPY |
				   DCP_CONTROL0_DECR_SEMAPHORE |
				   DCP_CONTROL0_INTERRUPT_ENABLE;
	save_context_desc->ctrl1 = 0;
	save_context_desc->payload = NULL;
	save_context_desc->status = 0;
	save_context_desc->buff_size = DCP_CONTEXT_CHANNEL_SIZE;
	save_context_desc->src_buffer = hw_context_buffer.data + offset;
	save_context_desc->dest_buffer = dcp_data->sw_context_buffer.data;
	save_context_desc->next = 0;
}

/*
 * Start the DCP operation.
 * Chain 3 operations if context needs to be restore/save.
 *
 * @dcp_data   Structure containing dcp_descriptor configuration and channel to
 *	       use.
 */
static TEE_Result dcp_run(struct dcp_data *dcp_data)
{
	TEE_Result ret = TEE_SUCCESS;
	unsigned int timeout = 0;
	uint32_t val = 0;
	struct dcp_descriptor restore_context_desc = { };
	struct dcp_descriptor save_context_desc = { };
	unsigned int incr_semaphore = 1;

	/* For Hash and AES CBC, context need to be restore and save */
	if (dcp_data->desc.ctrl0 & DCP_CONTROL0_ENABLE_HASH ||
	    dcp_data->desc.ctrl1 & DCP_CONTROL1_CIPHER_MODE_CBC) {
		/*
		 * DCP channel semaphore register will be incremented by 3
		 * because 3 operations will be chained:
		 *	1.restore_context(dcp memory copy)
		 *	2.operation(dcp hash or aes)
		 *	3.save_context
		 */
		incr_semaphore = 3;
		/* save_context will be executed after the operation */
		dcp_data->desc.next = virt_to_phys(&save_context_desc);
		/* Configuration of the context descriptors */
		dcp_context_switch_desc(&save_context_desc,
					&restore_context_desc, dcp_data);
		/* Cache operation for the context descriptors */
		cache_operation(TEE_CACHECLEAN, &save_context_desc,
				sizeof(dcp_data->desc));
		cache_operation(TEE_CACHECLEAN, &restore_context_desc,
				sizeof(dcp_data->desc));
		cache_operation(TEE_CACHEINVALIDATE, hw_context_buffer.data,
				hw_context_buffer.size);
		cache_operation(TEE_CACHEINVALIDATE,
				dcp_data->sw_context_buffer.data,
				dcp_data->sw_context_buffer.size);
	}

	cache_operation(TEE_CACHECLEAN, dcp_data->desc.src_buffer,
			dcp_data->desc.buff_size);

	if (dcp_data->desc.dest_buffer)
		cache_operation(TEE_CACHEFLUSH, dcp_data->desc.dest_buffer,
				dcp_data->desc.buff_size);

	cache_operation(TEE_CACHEFLUSH, &dcp_data->desc,
			sizeof(dcp_data->desc));

	/* Enable clock if it's not done */
	dcp_clk_enable(true);

	/* Clear DCP_STAT IRQ field for the channel used by the operation */
	io_clrbits32(dcp_base + DCP_STAT, BIT32(dcp_data->channel));

	/* Clear CH_N_STAT */
	io_write32(dcp_base + DCP_CH_N_STAT(dcp_data->channel), 0x0);
	/* Update descriptor structure to be processed for the channel */
	if (incr_semaphore == 1)
		io_write32(dcp_base + DCP_CH_N_CMDPTR(dcp_data->channel),
			   virt_to_phys(&dcp_data->desc));
	else if (incr_semaphore == 3)
		io_write32(dcp_base + DCP_CH_N_CMDPTR(dcp_data->channel),
			   virt_to_phys(&restore_context_desc));
	/* Increment the semaphore to start the transfer */
	io_write32(dcp_base + DCP_CH_N_SEMA(dcp_data->channel), incr_semaphore);

	for (timeout = 0; timeout < DCP_MAX_TIMEOUT; timeout++) {
		dcp_udelay(10);
		val = io_read32(dcp_base + DCP_STAT);
		if (val & BIT(dcp_data->channel))
			break;
	}

	val = io_read32(dcp_base + DCP_CH_N_STAT(dcp_data->channel));
	if (val & DCP_CH_STAT_ERROR_MASK) {
		EMSG("Error operation, 0x%" PRIx32, val);
		ret = TEE_ERROR_GENERIC;
	}

	if (timeout == DCP_MAX_TIMEOUT) {
		EMSG("Timeout finished before operation");
		ret = TEE_ERROR_GENERIC;
	}

	dcp_clk_enable(false);

	if (dcp_data->desc.dest_buffer)
		cache_operation(TEE_CACHEINVALIDATE, dcp_data->desc.dest_buffer,
				dcp_data->desc.buff_size);

	return ret;
}

/*
 * AES128-CMAC subkey generation algorithm
 *
 * @subkey        [out] Subkey generated
 * @message_size  Size of the message in bytes
 * @aes           AES operation configuration
 */
static TEE_Result aes_cmac_subkey_generation(uint8_t *subkey,
					     size_t message_size,
					     struct dcp_aesdata *aes)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	static const uint8_t const_zero[DCP_AES128_KEY_SIZE] = { };
	uint8_t k0[DCP_AES128_KEY_SIZE] = { };
	uint8_t buffer[DCP_AES128_KEY_SIZE] = { };

	if (!subkey) {
		EMSG("Bad parameters,subkey is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!aes) {
		EMSG("Bad parameters, aes is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (message_size > DCP_AES128_BUFFER_SIZE) {
		EMSG("Bad parameters, message_size should be <= 16 bytes");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/*
	 * 1st step
	 * Generate k0 = AES-128(OTP_KEY, const_Zero)
	 */
	ret = dcp_aes_do_update(aes, const_zero, k0, DCP_AES128_KEY_SIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("k0 generation failed");
		return ret;
	}

	/*
	 * 2nd step: Generate subkey
	 * If message_size = 128bit subkey = k1
	 *    message_size < 128 subkey = k2
	 * If msb(k0) = 0, k1 = k0 << 1
	 *    msb(k0) = 1, k1 = (k0 << 1) ^ DCP_AES128CMAC_RB_CONST
	 * If msb(k1) = 0, k2 = k1 << 1
	 *    msb(k1) = 1, k2 = (k1 << 1) ^ DCP_AES128CMAC_RB_CONST
	 */
	dcp_left_shift_buffer(buffer, k0, DCP_AES128_KEY_SIZE);

	if (k0[0] & DCP_MSB_INT8)
		buffer[DCP_AES128_KEY_SIZE - 1] ^= DCP_AES128CMAC_RB_CONST;

	if (message_size == DCP_AES128_BUFFER_SIZE) {
		memcpy(subkey, buffer, DCP_AES128_KEY_SIZE);
	} else if (message_size < DCP_AES128_BUFFER_SIZE) {
		dcp_left_shift_buffer(subkey, buffer, DCP_AES128_KEY_SIZE);
		if (buffer[0] & DCP_MSB_INT8)
			subkey[DCP_AES128_KEY_SIZE - 1] ^=
				DCP_AES128CMAC_RB_CONST;
	}

	return ret;
}

TEE_Result dcp_store_key(uint32_t *key, unsigned int index)
{
	uint32_t val = 0;
	unsigned int i = 0;
	uint32_t key_store_except = 0;

	if (!key) {
		EMSG("Bad parameters, key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (index > 3) {
		EMSG("Bad parameters, index has to be 0, 1, 2 or 3");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	key_store_except = cpu_spin_lock_xsave(&key_store_spinlock);

	dcp_clk_enable(true);

	val = DCP_SRAM_KEY_INDEX(index);
	io_write32(dcp_base + DCP_KEY, val);

	/*
	 * Key is stored as four uint32 values, starting with subword0
	 * (least-significant word)
	 */
	for (i = 0; i < DCP_SRAM_KEY_NB_SUBWORD; i++) {
		val = TEE_U32_TO_BIG_ENDIAN(key[i]);
		io_write32(dcp_base + DCP_KEYDATA, val);
	}

	dcp_clk_enable(false);

	cpu_spin_unlock_xrestore(&key_store_spinlock, key_store_except);

	return TEE_SUCCESS;
}

TEE_Result dcp_aes_cmac(uint8_t *message, size_t message_size, uint8_t *output,
			struct dcp_cipher_init *init)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint8_t subkey[DCP_AES128_KEY_SIZE] = { };
	uint8_t buffer[DCP_AES128_BUFFER_SIZE] = { };
	struct dcp_aesdata aes = { };
	unsigned int i = 0;

	if (!message) {
		EMSG("Bad parameters, message is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (message_size > DCP_AES128_BUFFER_SIZE) {
		EMSG("Bad parameters, message_size should be <= 16 bytes");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!output) {
		EMSG("Bad parameters, output is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!init) {
		EMSG("Bad parameters, init is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = dcp_aes_do_init(&aes, init);
	if (ret != TEE_SUCCESS) {
		EMSG("dcp_aes_do_init failed");
		return ret;
	}

	ret = aes_cmac_subkey_generation(subkey, message_size, &aes);
	if (ret != TEE_SUCCESS) {
		EMSG("aes_cmac_subkey_generation failed");
		dcp_aes_do_final(&aes);
		return ret;
	}

	memcpy(buffer, message, message_size);

	/* Mask message with subkey */
	for (i = 0; i < DCP_AES128_BUFFER_SIZE; i++)
		buffer[i] ^= subkey[i];

	ret = dcp_aes_do_update(&aes, buffer, output, DCP_AES128_KEY_SIZE);

	dcp_aes_do_final(&aes);

	return ret;
}

TEE_Result dcp_aes_do_init(struct dcp_aesdata *aes,
			   struct dcp_cipher_init *init)
{
	struct dcp_descriptor *desc = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!init) {
		EMSG("Bad parameters, init is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!aes) {
		EMSG("Bad parameters, aes is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = dcp_calloc_align_buf(&aes->dcp_data.sw_context_buffer,
				   DCP_CONTEXT_CHANNEL_SIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("AES sw_context_buffer allocation failed");
		return ret;
	}

	desc = &aes->dcp_data.desc;

	memset(aes->buffer, 0, DCP_AES128_IV_SIZE + DCP_AES128_KEY_SIZE);

	/* DCP operation configuration */
	aes->payload_size = 0;
	aes->dcp_data.channel = init->channel;
	if (aes->dcp_data.channel == DCP_CHANN_ANY)
		aes->op_state.any_channel = true;
	else
		aes->op_state.any_channel = false;

	desc->ctrl0 = DCP_CONTROL0_DECR_SEMAPHORE | DCP_CONTROL0_ENABLE_CIPHER |
		      DCP_CONTROL0_INTERRUPT_ENABLE;
	desc->ctrl1 = DCP_CONTROL1_CIPHER_SELECT_AES128;

	if (init->op == ENCRYPT)
		desc->ctrl0 |= DCP_CONTROL0_CIPHER_ENCRYPT;

	if (init->key_mode == OTP) {
		desc->ctrl0 |= DCP_CONTROL0_OTP_KEY;
		desc->ctrl1 |= DCP_CONTROL1_KEY_SELECT_OTP_CRYPTO;
	} else if (init->key_mode == PAYLOAD) {
		desc->ctrl0 |= DCP_CONTROL0_PAYLOAD_KEY;
		aes->payload_size += DCP_AES128_KEY_SIZE;
		memcpy(aes->buffer, init->key, DCP_AES128_KEY_SIZE);
	} else {
		desc->ctrl1 |= SHIFT_U32(init->key_mode, 8);
	}

	if (init->mode == CBC) {
		desc->ctrl0 |= DCP_CONTROL0_CIPHER_INIT | DCP_CONTROL0_CHAIN;
		desc->ctrl1 |= DCP_CONTROL1_CIPHER_MODE_CBC;
		memcpy(aes->buffer + aes->payload_size, init->iv,
		       DCP_AES128_IV_SIZE);
		aes->payload_size += DCP_AES128_IV_SIZE;
	}

	desc->src_buffer = NULL;
	desc->dest_buffer = NULL;
	desc->status = 0;
	desc->buff_size = 0;
	desc->next = virt_to_phys(desc);
	aes->op_state.init = true;

	return ret;
}

TEE_Result dcp_aes_do_update(struct dcp_aesdata *aes, const uint8_t *src,
			     uint8_t *dst, size_t size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	struct dcp_align_buf output = { };
	unsigned int nb_block = 0;
	unsigned int idx = 0;
	uint8_t data_block[DCP_AES_BLOCK_SIZE] = { };
	struct dcp_descriptor *desc = NULL;

	if (!aes) {
		EMSG("Bad parameters, aes is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/* Check if dcp_aes_do_init() has been called before */
	if (!aes->op_state.init) {
		EMSG("Error, please call dcp_aes_do_init() before");
		return TEE_ERROR_ACCESS_DENIED;
	}
	if (size % DCP_AES128_BUFFER_SIZE || !size) {
		EMSG("Bad parameters, size has to be a multiple of 16bytes");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!src) {
		EMSG("Bad parameters, src is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!dst) {
		EMSG("Bad parameters, dst is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = dcp_calloc_align_buf(&output, size);
	if (ret != TEE_SUCCESS) {
		EMSG("Output aligned buffer allocation failed");
		return ret;
	}

	desc = &aes->dcp_data.desc;

	nb_block = size / DCP_AES_BLOCK_SIZE;
	if (!nb_block) {
		nb_block = 1;
		desc->buff_size = size;
	} else {
		desc->buff_size = DCP_AES_BLOCK_SIZE;
	}

	/* Lock the channel */
	ret = dcp_lock_channel(&aes->op_state, &aes->dcp_data.channel);
	if (ret != TEE_SUCCESS) {
		EMSG("Channel is busy, can't start operation now");
		goto out;
	}

	desc->src_buffer = data_block;

	for (idx = 0; idx < nb_block; idx++) {
		memcpy(data_block, src + idx * DCP_AES_BLOCK_SIZE,
		       DCP_AES_BLOCK_SIZE);

		desc->dest_buffer = output.data + idx * DCP_AES_BLOCK_SIZE;
		desc->payload = aes->buffer;

		if (aes->payload_size)
			cache_operation(TEE_CACHECLEAN,
					aes->dcp_data.desc.payload,
					aes->payload_size);

		ret = dcp_run(&aes->dcp_data);

		if (ret != TEE_SUCCESS)
			goto out_unlock;

		if (desc->ctrl0 & DCP_CONTROL0_CIPHER_INIT) {
			desc->ctrl0 &= ~DCP_CONTROL0_CIPHER_INIT;
			aes->payload_size -= DCP_AES128_IV_SIZE;
		}
	}

	if (ret == TEE_SUCCESS)
		memcpy(dst, output.data, output.size);

out_unlock:
	dcp_unlock_channel(aes->dcp_data.channel);
out:
	dcp_free(&output);

	return ret;
}

void dcp_aes_do_final(struct dcp_aesdata *aes)
{
	if (aes) {
		aes->op_state.init = false;
		dcp_free(&aes->dcp_data.sw_context_buffer);
	}

	DMSG("End AES operation");
}

TEE_Result dcp_sha_do_init(struct dcp_hashdata *hashdata)
{
	struct dcp_descriptor *desc = NULL;
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (!hashdata) {
		EMSG("Bad parameters, hashdata is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (hashdata->hash_check == DCP_SHA_CHECK && !hashdata->check_value) {
		EMSG("DCP check value is NULL and DCP CHECK is set");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ret = dcp_calloc_align_buf(&hashdata->dcp_data.sw_context_buffer,
				   DCP_CONTEXT_CHANNEL_SIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("HASH sw_context_buffer allocation failed");
		return ret;
	}

	desc = &hashdata->dcp_data.desc;

	/* DCP descriptor init */
	desc->status = 0;
	desc->payload = NULL;
	desc->dest_buffer = NULL;
	desc->ctrl0 = DCP_CONTROL0_ENABLE_HASH | DCP_CONTROL0_INTERRUPT_ENABLE |
		      DCP_CONTROL0_DECR_SEMAPHORE | DCP_CONTROL0_HASH_INIT |
		      DCP_CONTROL0_CHAIN;
	desc->ctrl1 = hash_alg[hashdata->hash_id].type;
	desc->buff_size = 0;
	desc->next = 0;
	desc->src_buffer = NULL;
	hashdata->block_data_filled = 0;
	hashdata->paddr_block_data = virt_to_phys(hashdata->block_data);
	hashdata->block_data_size = DCP_SHA_BLOCK_SIZE;

	if (hashdata->dcp_data.channel == DCP_CHANN_ANY)
		hashdata->op_state.any_channel = true;
	else
		hashdata->op_state.any_channel = false;

	memset(hashdata->block_data, 0, hashdata->block_data_size);

	hashdata->op_state.init = true;

	return ret;
}

TEE_Result dcp_sha_do_update(struct dcp_hashdata *hashdata, const uint8_t *data,
			     size_t len)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	uint8_t data_block[DCP_SHA_BLOCK_SIZE] = { };
	size_t size = 0;
	size_t clen = 0;
	unsigned int nb_block = 0;
	unsigned int idx = 0;
	struct dcp_descriptor *desc = NULL;

	if (!hashdata) {
		EMSG("Bad parameters, hashdata is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	/* Check if dcp_sha_do_init() has been called before */
	if (!hashdata->op_state.init) {
		EMSG("Error, please call dcp_sha_do_init() before");
		return TEE_ERROR_ACCESS_DENIED;
	}
	if (!data) {
		EMSG("Bad parameters, data is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!len) {
		EMSG("Bad parameters, len is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	desc = &hashdata->dcp_data.desc;
	desc->src_buffer = data_block;

	nb_block = (len + hashdata->block_data_filled) / DCP_SHA_BLOCK_SIZE;
	if ((len + hashdata->block_data_filled) % DCP_SHA_BLOCK_SIZE &&
	    nb_block)
		nb_block++;

	/*
	 * If the data doesn't fill one data_block it's save in a buffer
	 * in the hashdata structure.
	 */
	if (!nb_block) {
		memcpy(hashdata->block_data + hashdata->block_data_filled, data,
		       len);
		hashdata->block_data_filled += len;
		return TEE_SUCCESS;
	}

	ret = dcp_lock_channel(&hashdata->op_state,
			       &hashdata->dcp_data.channel);
	if (ret != TEE_SUCCESS) {
		EMSG("Channel is busy, can't start operation now");
		return ret;
	}

	for (idx = 0; idx < nb_block; idx++) {
		if (!idx && hashdata->block_data_filled) {
			/* Use hashdata->block_data if present to */
			memcpy(data_block, hashdata->block_data,
			       hashdata->block_data_filled);
			/* clen = remaining size to fill a block */
			clen = DCP_SHA_BLOCK_SIZE - hashdata->block_data_filled;
			/* Fill the buffer to its maximum */
			memcpy(data_block + hashdata->block_data_filled, data,
			       clen);
			/* Actual size in the local buffer (<= DCP_SHA_BLOCK) */
			size = clen + hashdata->block_data_filled;
			/* reset block_data_filled for last iteration */
			hashdata->block_data_filled = 0;
		} else if (idx != nb_block - 1) {
			/* Fill data block completely */
			memcpy(data_block, data + clen, DCP_SHA_BLOCK_SIZE);
			clen += DCP_SHA_BLOCK_SIZE;
			size = DCP_SHA_BLOCK_SIZE;
		} else if (idx == nb_block - 1) {
			/*
			 * Save data in hashdata structure to have data to
			 * submit during final operation
			 */
			memcpy(hashdata->block_data, data + clen, len - clen);
			hashdata->block_data_filled = len - clen;
			ret = TEE_SUCCESS;
			break;
		}

		desc->buff_size = size;
		ret = dcp_run(&hashdata->dcp_data);
		/*
		 * After the first call of DCP operation we need to unset
		 * DCP_CONTROL0_HASH_INIT
		 */
		if (desc->ctrl0 & DCP_CONTROL0_HASH_INIT)
			desc->ctrl0 &= ~DCP_CONTROL0_HASH_INIT;
	}

	dcp_unlock_channel(hashdata->dcp_data.channel);

	return ret;
}

TEE_Result dcp_sha_do_final(struct dcp_hashdata *hashdata, uint8_t *digest,
			    size_t digest_size)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	size_t payload_size = 0;
	unsigned int i = 0;
	struct dcp_descriptor *desc = NULL;
	struct dcp_align_buf payload = { };

	if (!hashdata) {
		EMSG("Bad parameters, hashdata is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!hashdata->op_state.init) {
		EMSG("Error, please call dcp_sha_do_init() before");
		return TEE_ERROR_ACCESS_DENIED;
	}
	if (!&hashdata->dcp_data.desc) {
		EMSG("Bad parameters, hashdata->dcp_data.desc is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (!digest) {
		EMSG("Bad parameters, digest is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}
	if (digest_size < hash_alg[hashdata->hash_id].size) {
		EMSG("Digest buffer size is to small, should be %" PRId32,
		     hash_alg[hashdata->hash_id].size);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	desc = &hashdata->dcp_data.desc;
	payload_size = hash_alg[hashdata->hash_id].size;
	ret = dcp_calloc_align_buf(&payload, payload_size);
	if (ret != TEE_SUCCESS) {
		EMSG("payload allocation failed");
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Set work packet for last iteration */
	desc->ctrl0 |= DCP_CONTROL0_HASH_TERM;
	desc->src_buffer = hashdata->block_data;
	desc->buff_size = hashdata->block_data_filled;
	desc->payload = payload.data;
	if (hashdata->hash_check == DCP_SHA_CHECK) {
		desc->ctrl0 |= DCP_CONTROL0_HASH_CHECK;
		/*
		 * Fill payload buffer with check value, for some reason DCP
		 * result is flipped
		 */
		for (i = 0; i < payload_size; i++)
			payload.data[i] =
				hashdata->check_value[payload_size - 1 - i];
		cache_operation(TEE_CACHECLEAN, desc->payload, payload_size);
	} else {
		cache_operation(TEE_CACHEFLUSH, desc->payload, payload_size);
	}

	ret = dcp_lock_channel(&hashdata->op_state,
			       &hashdata->dcp_data.channel);

	if (ret != TEE_SUCCESS) {
		EMSG("Channel is busy, can't start operation now");
		goto out;
	}

	ret = dcp_run(&hashdata->dcp_data);

	dcp_unlock_channel(hashdata->dcp_data.channel);

	/* Copy the result */
	if (hashdata->hash_check == DCP_SHA_NOCHECK) {
		cache_operation(TEE_CACHEINVALIDATE, desc->payload,
				payload_size);
		/* For some reason the result is flipped */
		for (i = 0; i < payload_size; i++)
			digest[i] = payload.data[payload_size - 1 - i];
	}

	/* Reset hashdata strcuture */
	hashdata->op_state.init = false;
	dcp_free(&hashdata->dcp_data.sw_context_buffer);

out:
	dcp_free(&payload);

	return ret;
}

#ifdef CFG_DT
static const char *const dt_ctrl_match_table[] = {
	"fsl,imx28-dcp",
	"fsl,imx6sl-dcp",
};

/*
 * Fetch DCP base address from DT
 *
 * @base        [out] DCP base address
 */
static TEE_Result dcp_pbase(paddr_t *base)
{
	void *fdt = NULL;
	int node = -1;
	unsigned int i = 0;

	fdt = get_dt();
	if (!fdt) {
		EMSG("DTB no present");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	for (i = 0; i < ARRAY_SIZE(dt_ctrl_match_table); i++) {
		node = fdt_node_offset_by_compatible(fdt, 0,
						     dt_ctrl_match_table[i]);
		if (node >= 0)
			break;
	}

	if (node < 0) {
		EMSG("DCP node not found err = 0x%" PRIx32, node);
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	if (_fdt_get_status(fdt, node) == DT_STATUS_DISABLED)
		return TEE_ERROR_ITEM_NOT_FOUND;

	if (!IS_ENABLED(CFG_IMX_DCP_NSEC)) {
		/* Force secure-status = "okay" and status="disabled" */
		if (dt_enable_secure_status(fdt, node)) {
			EMSG("Not able to set DCP Control DTB entry secure");
			return TEE_ERROR_NOT_SUPPORTED;
		}
	}

	*base = _fdt_reg_base_address(fdt, node);
	if (*base == DT_INFO_INVALID_REG) {
		EMSG("Unable to get the DCP Base address");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	return TEE_SUCCESS;
}
#endif /* CFG_DT */

TEE_Result dcp_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	paddr_t pbase = 0;

	if (driver_init)
		return TEE_SUCCESS;

	dcp_clk_enable(true);

	ret = dcp_pbase(&pbase);
	if (ret != TEE_SUCCESS)
		pbase = DCP_BASE;

	dcp_base = core_mmu_get_va(pbase, MEM_AREA_IO_SEC);
	if (!dcp_base) {
		EMSG("Unable to get DCP physical address");
		return TEE_ERROR_ITEM_NOT_FOUND;
	}

	/* Context switching buffer memory allocation */
	ret = dcp_calloc_align_buf(&hw_context_buffer, DCP_CONTEXT_BUFFER_SIZE);
	if (ret != TEE_SUCCESS) {
		EMSG("hw_context_buffer allocation failed");
		return ret;
	}

	/*
	 * Initialize control register
	 * Enable normal DCP operation (SFTRST & CLKGATE bits set to 0)
	 */
	io_write32(dcp_base + DCP_CTRL_CLR, DCP_CTRL_SFTRST | DCP_CTRL_CLKGATE);

	/* Copy context switching buffer address in DCP_CONTEXT register */
	io_write32(dcp_base + DCP_CTRL_SET,
		   DCP_CTRL_GATHER_RESIDUAL_WRITES |
			   DCP_CTRL_ENABLE_CONTEXT_SWITCHING);

	/* Enable all DCP channels */
	io_write32(dcp_base + DCP_CHANNELCTRL,
		   DCP_CHANNELCTRL_ENABLE_CHANNEL_MASK);

	/* Clear DCP_STAT register */
	io_write32(dcp_base + DCP_STAT_CLR, DCP_STAT_CLEAR);

	/* Copy context switching buffer address in DCP_CONTEXT register */
	io_write32(dcp_base + DCP_CONTEXT, (uint32_t)hw_context_buffer.paddr);

	driver_init = true;

	dcp_clk_enable(false);

	return ret;
}
