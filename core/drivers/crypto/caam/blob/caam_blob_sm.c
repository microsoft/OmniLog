// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019-2020 NXP
 *
 * Brief   CAAM Generation of an encapsulated DEK blob
 *         Use the CAAM Blob encapsulation from CAAM Secure Memory
 */
#include <caam_common.h>
#include <caam_sm.h>
#include <caam_utils_mem.h>
#include <caam_utils_status.h>
#include <drivers/caam/crypto_extension.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>

#ifdef CFG_PHYS_64BIT
#define BLOB_OPERATE_DESC_ENTRIES 12
#else
#define BLOB_OPERATE_DESC_ENTRIES 10
#endif

TEE_Result caam_blob_sm_encapsulate(struct crypto_blob *blob,
				    struct crypto_sm_page *sm_page)
{
	TEE_Result ret = TEE_ERROR_GENERIC;
	enum caam_status retstatus = CAAM_FAILURE;
	struct sm_page_addr sm_addr = {};
	struct caamdmaobj resblob = {};
	unsigned int opflags = 0;
	size_t outsize = 0;
	struct caam_jobctx jobctx = {};
	uint32_t *desc = NULL;

	if (!blob->payload.data || !blob->blob.data)
		return TEE_ERROR_BAD_PARAMETERS;

	outsize = blob->payload.length + BLOB_PAD_SIZE;

	switch (blob->type) {
	case BLOB_BLACK_CCM:
		opflags = PROT_BLOB_TYPE(BLACK_KEY) | PROT_BLOB_INFO(CCM);
		outsize = ROUNDUP(BLACK_KEY_CCM_SIZE(outsize), 16);
		break;

	case BLOB_BLACK_ECB:
		opflags = PROT_BLOB_TYPE(BLACK_KEY) | PROT_BLOB_INFO(ECB);
		outsize = ROUNDUP(BLACK_KEY_ECB_SIZE(outsize), 16);
		break;

	case BLOB_RED:
		break;

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (blob->blob.length < outsize) {
		BLOB_TRACE("Blob buffer too short expected %zu bytes", outsize);
		blob->blob.length = outsize;
		return TEE_ERROR_SHORT_BUFFER;
	}

	/* Re-allocate output buffer if alignment needed */
	ret = caam_dmaobj_output_sgtbuf(&resblob, blob->blob.data,
					blob->blob.length, outsize);
	if (ret)
		return ret;

	/* Allocate page(s) in one Secure Memory partition */
	ret = caam_sm_alloc(sm_page, &sm_addr);
	if (ret != CAAM_NO_ERROR) {
		BLOB_TRACE("Secure memory allocation error 0x%" PRIx32, ret);
		goto exit_operate;
	}

	/*
	 * Set the partition access rights for the group #1 to be
	 * a blob export/import
	 */
	/* Copy input data to encapsulate in Secure Memory allocated */
	memcpy((void *)sm_addr.vaddr, blob->payload.data, blob->payload.length);

	BLOB_DUMPBUF("Secure Memory", (void *)sm_addr.vaddr,
		     blob->payload.length);

	caam_sm_set_access_perm(sm_page, SM_GRP_BLOB, 0);

	/* Allocate the descriptor */
	desc = caam_calloc_desc(BLOB_OPERATE_DESC_ENTRIES);
	if (!desc) {
		BLOB_TRACE("CAAM Context Descriptor Allocation error");
		ret = TEE_ERROR_OUT_OF_MEMORY;
		goto exit_operate;
	}

	/*
	 * Create the Blob encapsulation descriptor
	 */
	caam_desc_init(desc);
	caam_desc_add_word(desc, DESC_HEADER(0));

	/*
	 * Command Protocol - The Key Modifier used when payload is
	 * in Secure Memory is only 64 bits and it's loaded in the
	 * Class 2 Key register at offset 12.
	 *
	 * Use the load immediata key value because key is small.
	 */
	caam_desc_add_word(desc, LD_IMM_OFF(CLASS_2, REG_KEY, 8, 12));
	caam_desc_add_word(desc, blob->key[0]);
	caam_desc_add_word(desc, blob->key[1]);

	/* Define the Input data sequence */
	caam_desc_add_word(desc, SEQ_IN_PTR(blob->payload.length));
	caam_desc_add_ptr(desc, sm_addr.paddr);

	/* Define the Output data sequence */
	caam_desc_seq_out(desc, &resblob);

	/* Define the encapsulation operation */
	caam_desc_add_word(desc, BLOB_ENCAPS | PROT_BLOB_SEC_MEM | opflags);

	BLOB_DUMPDESC(desc);

	cache_operation(TEE_CACHECLEAN, blob->payload.data,
			blob->payload.length);

	jobctx.desc = desc;
	retstatus = caam_jr_enqueue(&jobctx, NULL);

	if (retstatus == CAAM_NO_ERROR) {
		BLOB_TRACE("Done CAAM BLOB from Secure Memory encaps");

		blob->blob.length = caam_dmaobj_copy_to_orig(&resblob);

		BLOB_DUMPBUF("Blob Output", blob->blob.data, blob->blob.length);
		ret = caam_status_to_tee_result(retstatus);
	} else {
		BLOB_TRACE("CAAM Status 0x%08" PRIx32 "", jobctx.status);
		ret = TEE_ERROR_GENERIC;
	}

exit_operate:
	caam_sm_free_page(sm_page);
	caam_free_desc(&desc);
	caam_dmaobj_free(&resblob);

	return ret;
}
