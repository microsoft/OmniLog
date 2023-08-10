// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_imx7.c
 *
 * @brief   Implementation of the bus frequency scaling.\n
 *          Interface and initialization.
 */
/* Standard includes */
#include <string.h>

/* Global includes */
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>

/* Platform includes */
#include <platform_config.h>
#include <imx.h>
#include <imx_pm.h>
#include <mmdc.h>

/* Local include */
#include "busfreq_imx7.h"

/* Local data */
typedef void (*change_ddr_freq_func)(struct busfreq_info_mx7 *);
static change_ddr_freq_func change_ddr_freq;
static struct busfreq_info_mx7 *ddr_info;

/**
 * @brief   Setup the DDR3 info struct used in the busfreq assembly
 *          function.
 */
static void info_setup(void)
{
	ddr_info->ddr_type = imx_get_ddr_type();

	ddr_info->rev = soc_revision();

	/* Initialize the registers base address */
	ddr_info->ccm_base   = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	ddr_info->iomux_base = core_mmu_get_va(IOMUXC_GPR_BASE, MEM_AREA_IO_SEC);
	ddr_info->ddrc_base  = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC);
	ddr_info->ddrc_phy_base = core_mmu_get_va(DDRC_PHY_BASE,
						MEM_AREA_IO_SEC);
}

/**
 * @brief   Install the busfreq assembly function into the OCRAM
 *          and fill the busfreq data
 *
 * @retval  TEE_SUCCESS         Success
 * @retval  TEE_ERROR_GENERIC   Generic Error
 */
TEE_Result imx7_busfreq_init(void)
{
	int ddr_type;

	size_t function_size = 0;
	size_t data_size = 0;
	size_t page_size;

	uint32_t ocram_start = core_mmu_get_va(
				imx_get_ocram_tz_start_addr() +
				BUSFREQ_OCRAM_OFFSET, MEM_AREA_TEE_COHERENT);

	/* Get the type of memory used */
	ddr_type = imx_get_ddr_type();

	change_ddr_freq = &imx7_ddr_freq_change;
	function_size   = get_imx7_ddr_freq_change_size();
	data_size       = sizeof(struct busfreq_info_mx7);

	if (ddr_type == IMX_DDR_TYPE_DDR3) {
		DMSG("DDR3 mem function size=%d, data size=%d",
			function_size, data_size);
	} else if (ddr_type == IMX_DDR_TYPE_LPDDR2) {
		DMSG("LPDDR2 mem function size=%d, data size=%d",
			function_size, data_size);
	} else {
		DMSG("LPDDR3 mem function size=%d, data size=%d",
			function_size, data_size);
	}

	/* Determine the size to be allocated aligned on a 4K page */
	page_size = function_size + data_size;

	/*
	 * Check if there is enough place to install
	 * the busfreq data and function
	 */
	if (page_size > BUSFREQ_MAX_SIZE) {
		DMSG("Busfreq required %d bytes, available %d bytes",
			 page_size, BUSFREQ_MAX_SIZE);
		return TEE_ERROR_GENERIC;
	}

	/* Initialize the reserved page(s) with 0 */
	memset((void *)ocram_start, 0, page_size);
	/* Copy the DDR Change function in Secure non-DDR memory */
	memcpy((void *)ocram_start, (void *)((uint32_t)change_ddr_freq),
			function_size);

	/*
	 * Initialize address of ddr_info and change_ddr_freq function
	 * to be in OCRAM
	 */
	ddr_info = (struct busfreq_info_mx7 *)(ocram_start + function_size);
	change_ddr_freq = (change_ddr_freq_func)(ocram_start);

	info_setup();

	/* Clean D$ to ensure physical memory is correct */
	dcache_clean_range((void *)ocram_start, page_size);

	return TEE_SUCCESS;

}

/**
 * @brief   Change the bus frequency on i.MX7 device
 *          to the requested frequency \a freq and
 *          switch DLL off is \a dll_off = 1
 *
 * @param[in] freq     Frequency to switch to
 * @param[in] dll_off  switch DLL off or not - not used
 *
 * @retval  TEE_SUCCESS              No error
 * @retval  TEE_ERROR_NOT_SUPPORTED  Feature not supported
 */
TEE_Result imx7_busfreq_change(uint32_t freq, uint32_t dll_off __unused)
{
	uint32_t cpsr;
	uint32_t cpsr_if;

	DMSG("Change DDR frequency to %d Hz DLL", freq);

	if (!ddr_info)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Disable interrupts */
	cpsr = read_cpsr();
	write_cpsr(cpsr | (CPSR_I | CPSR_F));
	isb();

	/* Save the I/F bits */
	cpsr_if = cpsr & (CPSR_I | CPSR_F);

	ddr_info->freq = freq;
	dsb();

	change_ddr_freq(ddr_info);

	/* Restore cpsr I/F bits. Bit = 0 => enabled */
	cpsr = read_cpsr();
	cpsr &= ~(CPSR_I | CPSR_F);
	cpsr |= cpsr_if;
	write_cpsr(cpsr);

	return TEE_SUCCESS;
}
