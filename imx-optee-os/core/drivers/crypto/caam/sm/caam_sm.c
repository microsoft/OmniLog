// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM Secure Memory manager.
 */
#include <caam_common.h>
#include <caam_hal_ctrl.h>
#include <caam_hal_sm.h>
#include <caam_jr.h>
#include <caam_sm.h>
#include <caam_utils_mem.h>
#include <drivers/caam/crypto_extension.h>

/*
 * Secure memory module private data
 */
struct sm_privdata {
	vaddr_t baseaddr;  /* Secure memory base address */
	vaddr_t ctrl_addr; /* CAAM base address */
	vaddr_t jr_addr;   /* Job Ring base address */
	paddr_t jr_offset; /* Job Ring offset */
};

/*
 * Secure memory module private data reference
 */
static struct sm_privdata *sm_privdata;

/*
 * Get the page virtual address
 *
 * @page  Page number of the requested page address
 */
static vaddr_t get_page_va(unsigned int page)
{
	return sm_privdata->baseaddr +
	       caam_hal_sm_get_pages_size(sm_privdata->jr_addr, page);
}

enum caam_status caam_sm_alloc(struct crypto_sm_page *sm_page,
			       struct sm_page_addr *sm_addr)
{
	enum caam_status ret = CAAM_FAILURE;

	if (!sm_page)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = caam_hal_sm_check_page_partition(sm_privdata->jr_addr, sm_page);
	if (ret != CAAM_NO_ERROR) {
		SM_TRACE("Pages %u to %u or Partittion %u out of bounds",
			 sm_page->page, sm_page->page + sm_page->nb_pages - 1,
			 sm_page->partition);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	/* Is partition already allocated */
	if (!caam_hal_sm_is_prtn_free(sm_privdata->jr_addr,
				      sm_page->partition)) {
		SM_TRACE("Partition %u not available", sm_page->partition);
		return TEE_ERROR_BUSY;
	}

	/* Open all Secure Memory permission to all groups */
	caam_hal_sm_open_access_perm(sm_privdata->jr_addr, sm_page->partition);
	caam_hal_sm_set_access_all_group(sm_privdata->jr_addr,
					 sm_page->partition);

	ret = caam_hal_sm_allocate_page(sm_privdata->jr_addr, sm_page);
	if (ret != CAAM_NO_ERROR) {
		SM_TRACE("Error allocation Pages %u to %u into partition %u",
			 sm_page->page, sm_page->page + sm_page->nb_pages - 1,
			 sm_page->partition);
		/* Free all potientiel pages allocated before failure */
		caam_hal_sm_deallocate_pages(sm_privdata->jr_addr, sm_page);
		return TEE_ERROR_OUT_OF_MEMORY;
	}

	sm_addr->paddr =
		caam_hal_ctrl_get_smvaddr(sm_privdata->ctrl_addr,
					  sm_privdata->jr_offset) +
		caam_hal_sm_get_pages_size(sm_privdata->jr_addr, sm_page->page);
	sm_addr->vaddr = get_page_va(sm_page->page);

	SM_TRACE("Partition %u Pages %u to %u allocated @0x%" PRIxVA
		 " (phys 0x@%" PRIxPA,
		 sm_page->partition, sm_page->page,
		 sm_page->page + sm_page->nb_pages - 1, sm_addr->vaddr,
		 sm_addr->paddr);

	return CAAM_NO_ERROR;
}

TEE_Result caam_sm_free_partition(unsigned int partition)
{
	enum caam_status ret = CAAM_FAILURE;

	SM_TRACE("Free Secure Memory partition %u", partition);

	/*
	 * De-allocate partition. It automatically releases partition's pages
	 * to the pool of available pages. if the partition if marked as CSP,
	 * pages will be zeroized. If the partition is marked as PSP,
	 * partition and pages will not be de-allocated and a PSP will be
	 * returned
	 */
	if (caam_hal_sm_is_prtn_owned(sm_privdata->jr_addr, partition)) {
		/* De-allocate the partition */
		ret = caam_hal_sm_deallocate_partition(sm_privdata->jr_addr,
						       partition);
		if (ret != CAAM_NO_ERROR) {
			SM_TRACE("De-alloc partition %u error 0x%" PRIx32,
				 partition, ret);
			return TEE_ERROR_GENERIC;
		}
		return TEE_SUCCESS;
	}

	EMSG("Partition %u not owned by used JR", partition);
	return TEE_ERROR_ACCESS_DENIED;
}

TEE_Result caam_sm_free_page(struct crypto_sm_page *sm_page)
{
	enum caam_status ret = CAAM_FAILURE;

	SM_TRACE("Free Secure Memory pages %u to %u from partition %u",
		 sm_page->page, sm_page->page + sm_page->nb_pages,
		 sm_page->partition);

	if (caam_hal_sm_is_prtn_owned(sm_privdata->jr_addr,
				      sm_page->partition)) {
		ret = caam_hal_sm_deallocate_pages(sm_privdata->jr_addr,
						   sm_page);
		if (ret != CAAM_NO_ERROR) {
			SM_TRACE("De-alloc pages %u to %u error 0x%" PRIx32,
				 sm_page->page,
				 sm_page->page + sm_page->nb_pages, ret);
			return TEE_ERROR_GENERIC;
		}
		return TEE_SUCCESS;
	}

	EMSG("Partition %u not owned by used JR", sm_page->partition);
	return TEE_ERROR_ACCESS_DENIED;
}

enum caam_status caam_sm_set_access_perm(struct crypto_sm_page *sm_page,
					 unsigned int grp1_perm,
					 unsigned int grp2_perm)
{
	unsigned int grp1 = UINT32_MAX;
	unsigned int grp2 = UINT32_MAX;

	if (!sm_page)
		return CAAM_BAD_PARAM;

	/* Do we owned the partition */
	if (!caam_hal_sm_is_prtn_owned(sm_privdata->jr_addr,
				       sm_page->partition)) {
		SM_TRACE("Partition %d not owned by used JR",
			 sm_page->partition);
		return CAAM_FAILURE;
	}

	/*
	 * Set ourself to access Secure Memory group 1 and/or group 2
	 * function if @grp1_perm and/or @grp2_perm not equal 0.
	 *
	 * The Access Group is related to the Job Ring owner setting without
	 * the Secure Bit setting already managed by the Job Ring.
	 */
	if (grp1_perm)
		grp1 = JROWN_ARM_NS;

	if (grp2_perm)
		grp2 = JROWN_ARM_NS;

	caam_hal_sm_set_access_group(sm_privdata->jr_addr, sm_page->partition,
				     grp1, grp2);
	caam_hal_sm_set_access_perm(sm_privdata->jr_addr, sm_page->partition,
				    grp1_perm, grp2_perm);

	return CAAM_NO_ERROR;
}

enum caam_status caam_sm_init(struct caam_jrcfg *jrcfg)
{
	enum caam_status retstatus = CAAM_FAILURE;

	/* Allocate the secure memory private data */
	sm_privdata = caam_calloc(sizeof(struct sm_privdata));
	if (!sm_privdata) {
		SM_TRACE("Private Data allocation error");
		return CAAM_OUT_MEMORY;
	}

	sm_privdata->baseaddr = caam_hal_sm_get_base();
	sm_privdata->ctrl_addr = jrcfg->base;
	sm_privdata->jr_addr = jrcfg->base + jrcfg->offset;
	sm_privdata->jr_offset = jrcfg->offset;

	SM_TRACE("Secure Memory Base address = 0x%" PRIxVA,
		 sm_privdata->baseaddr);
	SM_TRACE("CAAM controller address = 0x%" PRIxVA,
		 sm_privdata->ctrl_addr);
	SM_TRACE("CAAM Job Ring address = 0x%" PRIxVA, sm_privdata->jr_addr);

	if (!sm_privdata->baseaddr) {
		EMSG("Unable to map CAAM Secure Memory");
		retstatus = CAAM_FAILURE;
	} else {
		retstatus = CAAM_NO_ERROR;
	}

	if (retstatus != CAAM_NO_ERROR)
		caam_free(sm_privdata);

	return retstatus;
}
