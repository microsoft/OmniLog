/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_imx7.h
 *
 * @brief   Busfreq imx7 header.
 */

#ifndef __BUSFREQ_IMX7_H__
#define __BUSFREQ_IMX7_H__

#ifndef __ASSEMBLER__
/**
 * @brief   Definition of the structure used during the bus frequency
 *          operation.
 *          This structure must be inline with the assembly code offset
 *          definition.
 */
struct busfreq_info_mx7 {
	uint32_t freq;
	uint16_t ddr_type;
	uint16_t rev;
	uint32_t ccm_base;
	uint32_t iomux_base;
	uint32_t ddrc_base;
	uint32_t ddrc_phy_base;
} __aligned(8);


TEE_Result imx7_busfreq_init(void);
TEE_Result imx7_busfreq_change(uint32_t freq, uint32_t dll_off);

void imx7_ddr_freq_change(struct busfreq_info_mx7 *info);
size_t get_imx7_ddr_freq_change_size(void);
#endif

#endif
