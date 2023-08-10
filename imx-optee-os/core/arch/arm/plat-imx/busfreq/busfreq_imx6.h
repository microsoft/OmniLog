/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_imx6.h
 *
 * @brief   Busfreq imx6 header.
 */
#ifndef __BUSFREQ_IMX6_H__
#define __BUSFREQ_IMX6_H__

#ifndef __ASSEMBLER__
/**
 * @brief   Definition of the structure used during the bus frequency
 *          operation.
 *          This structure must be inline with the assembly code offset
 *          definition.
 */
struct busfreq_info_mx6 {
	uint32_t cpu_type;
	uint32_t freq;
	uint32_t dll_off;
	uint32_t (*ddr_settings)[2];
	uint32_t ddr_settings_size;
	uint32_t (*ddr_calibration)[2];
	uint32_t ddr_calibration_size;
	uint32_t (*iomux_offsets)[2];
	uint32_t iomux_offsets_size;
	uint32_t ccm_base;
	uint32_t iomux_base;
	uint32_t mmdc_base;
	uint32_t pl310_v_base;
	uint32_t ttbr1;
} __aligned(8);

TEE_Result imx6_busfreq_init(void);
TEE_Result imx6_busfreq_change(uint32_t freq, uint32_t dll_off);

void imx6_ddr3_freq_change(struct busfreq_info_mx6 *info);
size_t get_imx6_ddr3_freq_change_size(void);
void imx6_lpddr2_freq_change(struct busfreq_info_mx6 *info);
size_t get_imx6_lpddr2_freq_change_size(void);
#endif
/*
 * Define the CPU ID bit mask needed in the Assembly code
 */
#define BUSFREQ_CPU_MX6UL		BIT32(0)
#define BUSFREQ_CPU_MX6QP		BIT32(1)
#define BUSFREQ_CPU_MX6SX		BIT32(2)

#endif
