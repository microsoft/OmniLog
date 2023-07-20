// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_imx7_defines.c
 *
 * @brief   Implementation of the bus frequency scaling.\n
 *          Definition of the struct busfreq_info_mx7 field to
 *          be shared with the assembly code
 */

/* Global includes */
#include <gen-asm-defines.h>
#include <tee_api_types.h>

/* Local include */
#include "busfreq_imx7.h"

/*
 * Define the offset of the structure busfreq_info_mx7
 * defined in the busfreq_imx7.h file
 */
DEFINES
{
	DEFINE(BUSFREQ_INFO_FREQ,
		offsetof(struct busfreq_info_mx7, freq));
	DEFINE(BUSFREQ_INFO_DDR_TYPE,
		offsetof(struct busfreq_info_mx7, ddr_type));
	DEFINE(BUSFREQ_INFO_REV,
		offsetof(struct busfreq_info_mx7, rev));
	DEFINE(BUSFREQ_INFO_CCM_BASE,
		offsetof(struct busfreq_info_mx7, ccm_base));
	DEFINE(BUSFREQ_INFO_IOMUX_BASE,
		offsetof(struct busfreq_info_mx7, iomux_base));
	DEFINE(BUSFREQ_INFO_DDRC_BASE,
		offsetof(struct busfreq_info_mx7, ddrc_base));
	DEFINE(BUSFREQ_INFO_DDRC_PHY_BASE,
		offsetof(struct busfreq_info_mx7, ddrc_phy_base));
}

