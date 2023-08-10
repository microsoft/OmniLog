// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_imx6.c
 *
 * @brief   Implementation of the bus frequency scaling.\n
 *          Interface and initialization.
 */
/* Standard includes */
#include <string.h>

/* Global includes */
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>

/* Platform includes */
#include <platform_config.h>
#include <imx.h>
#include <imx_pm.h>
#include <mmdc.h>

/* Local include */
#include "busfreq_imx6.h"

static uint32_t ddr3_dll_mx6sx_ul[][2] = {
	{MX6_MMDC_MDCFG0,	 0x0},
	{MX6_MMDC_MDCFG1,	 0x0},
	{MX6_MMDC_MDMISC,    0x0},
	{MX6_MMDC_MDSCR,	 0x04008032},
	{MX6_MMDC_MDSCR,	 0x00048031},
	{MX6_MMDC_MDSCR,	 0x05208030},
	{MX6_MMDC_MDSCR,	 0x04008040},
	{MX6_MMDC_MPODTCTRL, 0x0},
};

static uint32_t ddr3_calibration_mx6sx_ul[][2] = {
	{MX6_MMDC_MPDGCTRL0, 0x0},
	{MX6_MMDC_MPDGCTRL1, 0x0},
	{MX6_MMDC_MPRDDLCTL, 0x0},
	{MX6_MMDC_MPWRDLCTL, 0x0},
};

static uint32_t iomux_offsets_mx6sx[][2] = {
	{0x330, 0x0},
	{0x334, 0x0},
	{0x338, 0x0},
	{0x33c, 0x0},
};

static uint32_t iomux_offsets_mx6ul[][2] = {
	{0x280, 0x0},
	{0x284, 0x0},
};

static uint32_t ddr3_calibration[][2] = {
	{MX6_MMDC_MPDGCTRL0,					0x0},
	{MX6_MMDC_MPDGCTRL1,					0x0},
	{MX6_MMDC_MPDGCTRL0 + MX6_MMDC2_OFFSET, 0x0},
	{MX6_MMDC_MPDGCTRL1 + MX6_MMDC2_OFFSET, 0x0},
	{MX6_MMDC_MPRDDLCTL,					0x0},
	{MX6_MMDC_MPRDDLCTL + MX6_MMDC2_OFFSET, 0x0},
	{MX6_MMDC_MPWRDLCTL,					0x0},
	{MX6_MMDC_MPWRDLCTL + MX6_MMDC2_OFFSET, 0x0},
};

static uint32_t ddr3_dll_mx6q[][2] = {
	{MX6_MMDC_MDCFG0,	 0x0},
	{MX6_MMDC_MDCFG1,	 0x0},
	{MX6_MMDC_MDMISC,    0x0},
	{MX6_MMDC_MDSCR,	 0x04088032},
	{MX6_MMDC_MDSCR,	 0x0408803a},
	{MX6_MMDC_MDSCR,	 0x08408030},
	{MX6_MMDC_MDSCR,	 0x08408038},
	{MX6_MMDC_MPODTCTRL, 0x0},
};

static uint32_t ddr3_dll_mx6dl[][2] = {
	{MX6_MMDC_MDCFG0,	 0x0},
	{MX6_MMDC_MDCFG1,	 0x0},
	{MX6_MMDC_MDMISC,    0x0},
	{MX6_MMDC_MDSCR,	 0x04008032},
	{MX6_MMDC_MDSCR,	 0x0400803a},
	{MX6_MMDC_MDSCR,	 0x07208030},
	{MX6_MMDC_MDSCR,	 0x07208038},
	{MX6_MMDC_MPODTCTRL, 0x0},
};

static uint32_t iomux_offsets_mx6dl[][2] = {
	{0x4BC, 0x0},
	{0x4C0, 0x0},
	{0x4C4, 0x0},
	{0x4C8, 0x0},
	{0x4CC, 0x0},
	{0x4D0, 0x0},
	{0x4D4, 0x0},
	{0x4D8, 0x0},
};

static uint32_t iomux_offsets_mx6q[][2] = {
	{0x5A8, 0x0},
	{0x5B0, 0x0},
	{0x524, 0x0},
	{0x51C, 0x0},
	{0x518, 0x0},
	{0x50C, 0x0},
	{0x5B8, 0x0},
	{0x5C0, 0x0},
};

/* Local data */
typedef void (*change_ddr_freq_func)(struct busfreq_info_mx6 *);
static change_ddr_freq_func change_ddr_freq;
static struct busfreq_info_mx6 *ddr_info;

/**
 * @brief   Setup the DDR3 info struct used in the busfreq assembly
 *          function.
 */
static void imx6_ddr3_info_setup(void)
{
	uint32_t idx;
	uint32_t (*table)[2];

	/* Set CPU ID field if needed */
	ddr_info->cpu_type = 0;

	if (soc_is_imx6ul() || soc_is_imx6ull())
		ddr_info->cpu_type = BUSFREQ_CPU_MX6UL;
	else if (soc_is_imx6dqp() || soc_is_imx6dq() || soc_is_imx6sdl())
		ddr_info->cpu_type = BUSFREQ_CPU_MX6QP;
	else if (soc_is_imx6sx())
		ddr_info->cpu_type = BUSFREQ_CPU_MX6SX;

	/* Initialize the registers base address */
	ddr_info->ccm_base   = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	ddr_info->iomux_base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC);
	ddr_info->mmdc_base  = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC);
#ifdef CFG_PL310
	/* Setup the PL310 virtual base address */
	ddr_info->pl310_v_base = pl310_base();
#endif
	if (soc_is_imx6dq() || soc_is_imx6dqp()) {
		/* Initialize the ddr_settings pointer and table */
		ddr_info->ddr_settings = (void *)((uint8_t *)ddr_info +
					sizeof(struct busfreq_info_mx6));
		ddr_info->ddr_settings_size = ARRAY_SIZE(ddr3_dll_mx6q);
		memcpy(ddr_info->ddr_settings, ddr3_dll_mx6q,
				sizeof(ddr3_dll_mx6q));

		/* Initialize the calibration pointer and table */
		ddr_info->ddr_calibration = (void *)(
					(uint8_t *)ddr_info->ddr_settings +
					sizeof(ddr3_dll_mx6q));
		ddr_info->ddr_calibration_size = ARRAY_SIZE(ddr3_calibration);
		memcpy(ddr_info->ddr_calibration, ddr3_calibration,
				sizeof(ddr3_calibration));

		/* Initialize the iomux pointer and table */
		ddr_info->iomux_offsets = (void *)(
					(uint8_t *)ddr_info->ddr_calibration +
					sizeof(ddr3_calibration));
		ddr_info->iomux_offsets_size = ARRAY_SIZE(iomux_offsets_mx6q);
		memcpy(ddr_info->iomux_offsets, iomux_offsets_mx6q,
				sizeof(iomux_offsets_mx6q));
	} else if (soc_is_imx6sdl()) {
		/* Initialize the ddr_settings pointer and table */
		ddr_info->ddr_settings = (void *)((uint8_t *)ddr_info +
					sizeof(struct busfreq_info_mx6));
		ddr_info->ddr_settings_size = ARRAY_SIZE(ddr3_dll_mx6dl);
		memcpy(ddr_info->ddr_settings, ddr3_dll_mx6dl,
				sizeof(ddr3_dll_mx6dl));

		/* Initialize the calibration pointer and table */
		ddr_info->ddr_calibration = (void *)(
					(uint8_t *)ddr_info->ddr_settings +
					sizeof(ddr3_dll_mx6dl));
		ddr_info->ddr_calibration_size = ARRAY_SIZE(ddr3_calibration);
		memcpy(ddr_info->ddr_calibration, ddr3_calibration,
				sizeof(ddr3_calibration));

		/* Initialize the iomux pointer and table */
		ddr_info->iomux_offsets = (void *)(
					(uint8_t *)ddr_info->ddr_calibration +
					sizeof(ddr3_calibration));
		ddr_info->iomux_offsets_size = ARRAY_SIZE(iomux_offsets_mx6dl);
		memcpy(ddr_info->iomux_offsets, iomux_offsets_mx6dl,
				sizeof(iomux_offsets_mx6dl));
	} else if (soc_is_imx6sx()) {
		/* Initialize the ddr_settings pointer and table */
		ddr_info->ddr_settings = (void *)((uint8_t *)ddr_info +
					sizeof(struct busfreq_info_mx6));
		ddr_info->ddr_settings_size = ARRAY_SIZE(ddr3_dll_mx6sx_ul);
		memcpy(ddr_info->ddr_settings, ddr3_dll_mx6sx_ul,
				sizeof(ddr3_dll_mx6sx_ul));

		/* Initialize the calibration pointer and table */
		ddr_info->ddr_calibration = (void *)(
					(uint8_t *)ddr_info->ddr_settings +
					sizeof(ddr3_dll_mx6sx_ul));
		ddr_info->ddr_calibration_size =
					ARRAY_SIZE(ddr3_calibration_mx6sx_ul);
		memcpy(ddr_info->ddr_calibration, ddr3_calibration_mx6sx_ul,
				sizeof(ddr3_calibration_mx6sx_ul));

		/* Initialize the iomux pointer and table */
		ddr_info->iomux_offsets = (void *)(
					(uint8_t *)ddr_info->ddr_calibration +
					sizeof(ddr3_calibration_mx6sx_ul));
		ddr_info->iomux_offsets_size = ARRAY_SIZE(iomux_offsets_mx6sx);
		memcpy(ddr_info->iomux_offsets, iomux_offsets_mx6sx,
				sizeof(iomux_offsets_mx6sx));
	} else if (soc_is_imx6ul() || soc_is_imx6ull()) {
		/* Initialize the ddr_settings pointer and table */
		ddr_info->ddr_settings = (void *)((uint8_t *)ddr_info +
					sizeof(struct busfreq_info_mx6));
		ddr_info->ddr_settings_size = ARRAY_SIZE(ddr3_dll_mx6sx_ul);
		memcpy(ddr_info->ddr_settings, ddr3_dll_mx6sx_ul,
				sizeof(ddr3_dll_mx6sx_ul));

		/* Initialize the calibration pointer and table */
		ddr_info->ddr_calibration = (void *)(
					(uint8_t *)ddr_info->ddr_settings +
					sizeof(ddr3_dll_mx6sx_ul));
		ddr_info->ddr_calibration_size =
					ARRAY_SIZE(ddr3_calibration_mx6sx_ul);
		memcpy(ddr_info->ddr_calibration, ddr3_calibration_mx6sx_ul,
				sizeof(ddr3_calibration_mx6sx_ul));

		/* Initialize the iomux pointer and table */
		ddr_info->iomux_offsets = (void *)(
					(uint8_t *)ddr_info->ddr_calibration +
					sizeof(ddr3_calibration_mx6sx_ul));
		ddr_info->iomux_offsets_size = ARRAY_SIZE(iomux_offsets_mx6ul);
		memcpy(ddr_info->iomux_offsets, iomux_offsets_mx6ul,
				sizeof(iomux_offsets_mx6ul));
	}

	/* Read the IO MUX */
	table = ddr_info->iomux_offsets;
	for (idx = 0; idx < ddr_info->iomux_offsets_size; idx++)
		table[idx][1] = io_read32(ddr_info->iomux_base + table[idx][0]);

	/* Read the DDR Settings */
	table = ddr_info->ddr_settings;
	for (idx = 0; idx < ddr_info->ddr_settings_size; idx++)
		if (table[idx][0] != MX6_MMDC_MDSCR)
			table[idx][1] = io_read32(ddr_info->mmdc_base +
						table[idx][0]);

	/* Read the Calibration Settings */
	table = ddr_info->ddr_calibration;
	for (idx = 0; idx < ddr_info->ddr_calibration_size; idx++)
		table[idx][1] = io_read32(ddr_info->mmdc_base + table[idx][0]);
}

/**
 * @brief   Install the busfreq assembly function into the OCRAM
 *          and fill the busfreq data
 *
 * @retval  TEE_SUCCESS         Success
 * @retval  TEE_ERROR_GENERIC   Generic Error
 */
TEE_Result imx6_busfreq_init(void)
{
	int ddr_type;

	size_t	function_size = 0;
	size_t	data_size = 0;
	size_t	page_size;

	uint32_t ocram_start;
	vaddr_t  tlb_ocram = core_mmu_get_va(
			imx_get_ocram_tz_start_addr() + IRAM_TBL_OFFSET,
			MEM_AREA_TEE_COHERENT);

	/*
	 * If the device is not 6SX using the OCRAM_S
	 * continue to copy data/function after the suspend
	 * and idle.
	 * Else, because the TTB1 used to execute the assembly functions
	 * idle/suspend/busfreq is 16 KBytes in OCRAM_S (16 KBytes max)
	 * the code/data and TTB are mixed and must care of TTB entries used.
	 * The Busfreq is installed at the end of the OCRAM_S
	 */
	if (!soc_is_imx6sx())
		ocram_start = core_mmu_get_va(
				imx_get_ocram_tz_start_addr() + BUSFREQ_OCRAM_OFFSET,
				MEM_AREA_TEE_COHERENT);
	else
		ocram_start = core_mmu_get_va(
				imx_get_ocram_tz_start_addr(),
				MEM_AREA_TEE_COHERENT);

	/* Get the type of memory used */
	ddr_type = imx_get_ddr_type();

	/*
	 * Get the BusFreq function to be installed and called
	 * specific OCRAM allocation for imx6q
	 */
	switch (ddr_type) {
	case IMX_DDR_TYPE_LPDDR2:
		change_ddr_freq = &imx6_lpddr2_freq_change;
		function_size   = get_imx6_lpddr2_freq_change_size();
		data_size       = sizeof(struct busfreq_info_mx6);
		DMSG("DDR2 mem function size=%d, data size=%d",
			  function_size, data_size);
		break;

	case IMX_DDR_TYPE_DDR3:
		change_ddr_freq = &imx6_ddr3_freq_change;
		function_size   = get_imx6_ddr3_freq_change_size();
		data_size       = sizeof(struct busfreq_info_mx6);
		if (soc_is_imx6dq() || soc_is_imx6dqp()) {
			data_size += sizeof(ddr3_dll_mx6q) +
					sizeof(ddr3_calibration) +
					sizeof(iomux_offsets_mx6q);
		} else if (soc_is_imx6sdl()) {
			data_size += sizeof(ddr3_dll_mx6dl) +
					sizeof(ddr3_calibration) +
					sizeof(iomux_offsets_mx6dl);
		} else if (soc_is_imx6sx()) {
			data_size += sizeof(ddr3_dll_mx6sx_ul) +
					sizeof(ddr3_calibration_mx6sx_ul) +
					sizeof(iomux_offsets_mx6sx);
		} else if (soc_is_imx6ul() || soc_is_imx6ull()) {
			data_size += sizeof(ddr3_dll_mx6sx_ul) +
					sizeof(ddr3_calibration_mx6sx_ul) +
					sizeof(iomux_offsets_mx6ul);
		} else {
			DMSG("No DDR3 configuration for this device");
			return TEE_ERROR_GENERIC;
		}

		DMSG("DDR3 mem function size=%d, data size=%d",
				  function_size, data_size);
		break;

	default:
		DMSG("Not supported ddr_type=%d", ddr_type);
		return TEE_ERROR_GENERIC;
	}

	/* Determine the size to be allocated aligned on a 4K page */
	page_size = function_size + data_size;

	if (soc_is_imx6sx())
		ocram_start += IRAM_6SX_S_SIZE - page_size;
	else if ((ocram_start + page_size) > tlb_ocram) {
		DMSG("Busfreq required %d bytes, available %ld bytes",
			 page_size, (tlb_ocram - ocram_start));
		return TEE_ERROR_GENERIC;
	}

	if (!soc_is_imx6sx())
		pm_ocram_free_area += page_size;

	/* Initialize the reserved page(s) with 0 */
	memset((void *)ocram_start, 0, page_size);
	/* Copy the DDR Change function in Secure non-DDR memory */
	memcpy((void *)ocram_start, (void *)((uint32_t)change_ddr_freq),
			function_size);

	/*
	 * Initialize address of ddr_info and change_ddr_freq function
	 * to be in OCRAM
	 */
	ddr_info = (struct busfreq_info_mx6 *)(ocram_start + function_size);
	change_ddr_freq = (change_ddr_freq_func)(ocram_start);

	if (ddr_type == IMX_DDR_TYPE_DDR3)
		imx6_ddr3_info_setup();

	/* Clean D$ to ensure physical memory is correct */
	dcache_clean_range((void *)ocram_start, page_size);

	return TEE_SUCCESS;
}

/**
 * @brief   Change the bus frequency on i.MX6 device
 *          to the requested frequency \a freq and
 *          switch DLL off is \a dll_off = 1
 *
 * @param[in] freq     Frequency to switch to
 * @param[in] dll_off  switch DLL off or not
 *
 * @retval  TEE_SUCCESS              No error
 * @retval  TEE_ERROR_NOT_SUPPORTED  Feature not supported
 */
TEE_Result imx6_busfreq_change(uint32_t freq, uint32_t dll_off)
{
	uint32_t cpsr;
	uint32_t cpsr_if;

	DMSG("Change DDR frequency to %d Hz DLL %s",
			freq, (dll_off ? "OFF" : "ON"));

	if (!ddr_info)
		return TEE_ERROR_NOT_SUPPORTED;

	/* Disable interrupts */
	cpsr = read_cpsr();
	write_cpsr(cpsr | (CPSR_I | CPSR_F));
	isb();

	/* Save the I/F bits */
	cpsr_if = cpsr & (CPSR_I | CPSR_F);

	ddr_info->freq		= freq;
	ddr_info->dll_off	= dll_off;
	dsb();

	change_ddr_freq(ddr_info);

	/* Restore cpsr I/F bits. Bit = 0 => enabled */
	cpsr = read_cpsr();
	cpsr &= ~(CPSR_I | CPSR_F);
	cpsr |= cpsr_if;
	write_cpsr(cpsr);

	return TEE_SUCCESS;
}
