// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_imx6_defines.c
 *
 * @brief   Implementation of the bus frequency scaling.\n
 *          Definition of the struct busfreq_info_mx6 field to
 *          be shared with the assembly code
 */

/* Global includes */
#include <gen-asm-defines.h>
#include <tee_api_types.h>

/* Local include */
#include "busfreq_imx6.h"

/*
 * Define the offset of the structure busfreq_info_mx6
 * defined in the busfreq_imx6.h file
 */
DEFINES
{
	DEFINE(BUSFREQ_INFO_CPU_TYPE,
		offsetof(struct busfreq_info_mx6, cpu_type));
	DEFINE(BUSFREQ_INFO_FREQ,
		offsetof(struct busfreq_info_mx6, freq));
	DEFINE(BUSFREQ_INFO_DLL_OFF,
		offsetof(struct busfreq_info_mx6, dll_off));
	DEFINE(BUSFREQ_INFO_DDR_SETTINGS,
		offsetof(struct busfreq_info_mx6, ddr_settings));
	DEFINE(BUSFREQ_INFO_DDR_SETTINGS_SIZE,
		offsetof(struct busfreq_info_mx6, ddr_settings_size));
	DEFINE(BUSFREQ_INFO_DDR_CALIBRATION,
		offsetof(struct busfreq_info_mx6, ddr_calibration));
	DEFINE(BUSFREQ_INFO_DDR_CALIBRATION_SIZE,
		offsetof(struct busfreq_info_mx6, ddr_calibration_size));
	DEFINE(BUSFREQ_INFO_IOMUX_OFFSETS,
		offsetof(struct busfreq_info_mx6, iomux_offsets));
	DEFINE(BUSFREQ_INFO_IOMUX_OFFSETS_SIZE,
		offsetof(struct busfreq_info_mx6, iomux_offsets_size));
	DEFINE(BUSFREQ_INFO_CCM_BASE,
		offsetof(struct busfreq_info_mx6, ccm_base));
	DEFINE(BUSFREQ_INFO_IOMUX_BASE,
		offsetof(struct busfreq_info_mx6, iomux_base));
	DEFINE(BUSFREQ_INFO_MMDC_BASE,
		offsetof(struct busfreq_info_mx6, mmdc_base));
	DEFINE(BUSFREQ_INFO_PL310_V_BASE,
		offsetof(struct busfreq_info_mx6, pl310_v_base));
	DEFINE(BUSFREQ_INFO_TTBR1_OFF,
		offsetof(struct busfreq_info_mx6, ttbr1));
}

