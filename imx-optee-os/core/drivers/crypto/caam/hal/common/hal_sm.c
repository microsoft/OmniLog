// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 * Brief   CAAM Secure Memory Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <kernel/boot.h>
#include <caam_common.h>
#include <caam_hal_sm.h>
#include <caam_io.h>
#include <mm/core_memprot.h>
#include <registers/version_regs.h>
#include <registers/sm_regs.h>

/*
 * Issue a Secure Memory Command to the @page and @partition.
 * Returns the command status when completed
 *
 * @jr_base    JR base address
 * @page       Memory Page
 * @partition  Partition
 * @cmd        Command to sent
 */
static uint32_t issue_cmd(vaddr_t jr_base, unsigned int page,
			  unsigned int partition, unsigned int cmd)
{
	unsigned int status = 0;

	/* Send cmd */
	io_caam_write32(jr_base + SM_SMCR, SM_SMCR_PAGE(page) |
						   SM_SMCR_PRTN(partition) |
						   SM_SMCR_CMD(cmd));

	/* Wait for the command to complete */
	do {
		status = io_caam_read32(jr_base + SM_SMCSR);
	} while (SM_SMCSR_CERR(status) == SM_SMCSR_CERR_NOT_COMPLETED);

	return status;
}

enum caam_status
caam_hal_sm_check_page_partition(vaddr_t jr_base,
				 struct crypto_sm_page *sm_page)
{
	unsigned int val = 0;

	val = io_caam_read32(jr_base + SMVID_MS);

	if (sm_page->page + sm_page->nb_pages > GET_SMVID_MS_MAX_NPAG(val) ||
	    sm_page->partition > GET_SMVID_MS_NPRT(val))
		return CAAM_BAD_PARAM;

	return CAAM_NO_ERROR;
}

size_t caam_hal_sm_get_pages_size(vaddr_t jr_base, unsigned int page)
{
	unsigned int pgsize = 0;

	pgsize = GET_SMVID_LS_PSIZ(io_caam_read32(jr_base + SMVID_LS));

	/* The number of bytes in a Secure Memory page is 2^pgsize KB */
	return (0x1 << (pgsize + 10)) * page;
}

unsigned int caam_hal_sm_is_prtn_free(vaddr_t jr_base, unsigned int partition)
{
	return SM_SMPO_OWNER(io_caam_read32(jr_base + SM_SMPO), partition) ==
	       SMPO_PO_AVAIL;
}

unsigned int caam_hal_sm_is_prtn_owned(vaddr_t jr_base, unsigned int partition)
{
	return SM_SMPO_OWNER(io_caam_read32(jr_base + SM_SMPO), partition) ==
	       SMPO_PO_OWNED;
}

void caam_hal_sm_set_access_all_group(vaddr_t jr_base, unsigned int partition)
{
	io_caam_write32(jr_base + SM_SMAG1(partition), UINT32_MAX);
	io_caam_write32(jr_base + SM_SMAG2(partition), UINT32_MAX);
}

void caam_hal_sm_set_access_group(vaddr_t jr_base, unsigned int partition,
				  unsigned int grp1, unsigned int grp2)
{
	uint32_t val = 0;

	if (grp1 != UINT32_MAX)
		val = SHIFT_U32(1, grp1);

	io_caam_write32(jr_base + SM_SMAG1(partition), val);

	val = 0;
	if (grp2 != UINT32_MAX)
		val = SHIFT_U32(1, grp2);

	io_caam_write32(jr_base + SM_SMAG2(partition), val);
}

void caam_hal_sm_open_access_perm(vaddr_t jr_base, unsigned int partition)
{
	io_caam_write32(jr_base + SM_SMAPR(partition),
			SM_SMAPR_GRP1(UINT8_MAX) | SM_SMAPR_GRP2(UINT8_MAX));
}

void caam_hal_sm_set_access_perm(vaddr_t jr_base, unsigned int partition,
				 unsigned int grp1_perm, unsigned int grp2_perm)
{
	io_caam_write32(jr_base + SM_SMAPR(partition),
			SM_SMAPR_GRP1(grp1_perm) | SM_SMAPR_GRP2(grp2_perm) |
				SM_SMAPR_CSP | SM_SMAPR_SMAP_LCK |
				SM_SMAPR_SMAG_LCK);
}

enum caam_status caam_hal_sm_allocate_page(vaddr_t jr_base,
					   struct crypto_sm_page *sm_page)
{
	unsigned int status = 0;
	unsigned int page = sm_page->page;

	for (; page < sm_page->page + sm_page->nb_pages; page++) {
		/* Check if the page is available, else return on error */
		status = issue_cmd(jr_base, page, 0, SM_SMCR_PAGE_INQ);
		if (SM_SMCSR_PO(status) != SM_SMCSR_PO_AVAILABLE)
			return CAAM_FAILURE;
	}

	for (page = sm_page->page; page < sm_page->page + sm_page->nb_pages;
	     page++) {
		/* Allocate page to partition */
		status = issue_cmd(jr_base, page, sm_page->partition,
				   SM_SMCR_PAGE_ALLOC);
		if (SM_SMCSR_AERR(status) != SM_SMCSR_AERR_NO_ERROR)
			return CAAM_FAILURE;
	}

	for (page = sm_page->page; page < sm_page->page + sm_page->nb_pages;
	     page++) {
		/* Check if the page is available, else return on error */
		status = issue_cmd(jr_base, page, 0, SM_SMCR_PAGE_INQ);
		if (SM_SMCSR_PO(status) != SM_SMCSR_PO_OWNED ||
		    SM_SMCSR_PRTN(status) != sm_page->partition)
			return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

enum caam_status caam_hal_sm_deallocate_partition(vaddr_t jr_base,
						  unsigned int partition)
{
	unsigned int status = 0;

	/* De-Allocate partition and so all partition's page */
	status = issue_cmd(jr_base, 0, partition, SM_SMCR_PARTITION_DEALLOC);
	if (SM_SMCSR_AERR(status) != SM_SMCSR_AERR_NO_ERROR)
		return CAAM_FAILURE;

	return CAAM_NO_ERROR;
}

enum caam_status caam_hal_sm_deallocate_pages(vaddr_t jr_base,
					      struct crypto_sm_page *sm_page)
{
	unsigned int status = 0;
	unsigned int page = sm_page->page;

	for (; page < sm_page->page + sm_page->nb_pages; page++) {
		/* De-Allocate page - partition not used */
		status = issue_cmd(jr_base, page, 0, SM_SMCR_PAGE_DEALLOC);
		if (SM_SMCSR_AERR(status) != SM_SMCSR_AERR_NO_ERROR)
			return CAAM_FAILURE;
	}

	return CAAM_NO_ERROR;
}

vaddr_t caam_hal_sm_get_base(void)
{
	vaddr_t sm_base = 0;
	void *fdt = NULL;

	fdt = get_dt();
	if (fdt)
		caam_hal_sm_get_base_dt(fdt, &sm_base);

	if (!sm_base) {
		sm_base = (vaddr_t)phys_to_virt(SECMEM_BASE, MEM_AREA_IO_SEC);
		if (!sm_base)
			if (core_mmu_add_mapping(MEM_AREA_IO_SEC, SECMEM_BASE,
						 CORE_MMU_PGDIR_SIZE))
				sm_base =
					(vaddr_t)phys_to_virt(SECMEM_BASE,
							      MEM_AREA_IO_SEC);
	}

	return sm_base;
}
