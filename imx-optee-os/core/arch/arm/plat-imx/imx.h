/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */
#ifndef PLAT_IMX_IMX_H
#define PLAT_IMX_IMX_H

#include <stdint.h>
#include <stdbool.h>

#define SOC_MX6SL	0x60
#define SOC_MX6DL	0x61
#define SOC_MX6SX	0x62
#define SOC_MX6Q	0x63
#define SOC_MX6UL	0x64
#define SOC_MX6ULL	0x65
#define SOC_MX6SLL	0x67
#define SOC_MX6D	0x6A
#define SOC_MX7D	0x72
#define SOC_MX7ULP	0xE1
#define SOC_MX8QX	0xE2
#define SOC_MX8QM	0xE3
#define SOC_MX8DXL	0xE4
#define SOC_MX8M	0x82

#ifndef __ASSEMBLER__
#include <tee_api_types.h>
#include <io.h>

uint32_t imx_get_src_gpr(int cpu);
void imx_set_src_gpr(int cpu, uint32_t val);
paddr_t imx_get_ocram_tz_start_addr(void);

bool soc_is_imx6(void);
bool soc_is_imx6sx(void);
bool soc_is_imx6sl(void);
bool soc_is_imx6sll(void);
bool soc_is_imx6ul(void);
bool soc_is_imx6ull(void);
bool soc_is_imx6sdl(void);
bool soc_is_imx6dq(void);
bool soc_is_imx6dqp(void);
bool soc_is_imx7ds(void);
bool soc_is_imx7ulp(void);
bool soc_is_imx8mq_b0_layer(void);
uint16_t soc_revision(void);
uint32_t imx_soc_type(void);
void imx_gpcv2_set_core1_pdn_by_software(void);
void imx_gpcv2_set_core1_pup_by_software(void);
void imx_gpcv2_set_core_pgc(bool enable, uint32_t offset);
bool imx_is_device_closed(void);
#ifdef CFG_PSCI_ARM32
void plat_cpu_wakeup_late(void);
#else
static inline void plat_cpu_wakeup_late(void)
{
}
#endif

#ifdef CFG_DT
void dt_debug(const char *node_str, const char *prop);
void dt_overwrite(const char *node_str, const char *prop_str,
		  const char *overw_str, uint32_t size_prop);
#endif
#endif /* __ASSEMBLER__ */
#endif
