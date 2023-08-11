// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2019 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <console.h>
#include <drivers/imx_snvs.h> 
#include <io.h>
#include <imx.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

static int imx_cpu_type = -1;
static int imx_soc_revision = -1;

#define CPU_TYPE(reg)		((reg & 0x00FF0000) >> 16)
#define SOC_REV_MAJOR(reg)	(((reg & 0x0000FF00) >> 8) + 1)
#define SOC_REV_MINOR(reg)	(reg & 0x0000000F)

static void imx_digproc(void)
{
	uint32_t digprog = 0;
	vaddr_t __maybe_unused base_addr = 0;

#if defined(CFG_MX7ULP)
	digprog = SOC_MX7ULP << 16;
#elif defined(CFG_MX8QX)
	digprog = SOC_MX8QX << 16;
#elif defined(CFG_MX8QM)
	digprog = SOC_MX8QM << 16;
#elif defined(CFG_MX8DXL)
	digprog = SOC_MX8DXL << 16;
#else
	base_addr = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);

	if (!base_addr)
		return;

	digprog = io_read32(base_addr + DIGPROG_OFFSET);
#ifdef SW_INFO_B1
	base_addr = core_mmu_get_va(OCOTP_BASE, MEM_AREA_IO_SEC);

	if (base_addr && (io_read32(base_addr + SW_INFO_B1) == SW_B1_MAGIC)) {
		// update soc revision for B1
		digprog |= 0x1;
	}
#endif /* SW_INFO_B1 */

#endif
	/* Set the CPU type */
	imx_cpu_type = CPU_TYPE(digprog);

#ifdef CFG_MX7
	imx_soc_revision = digprog & 0xFF;
#else
	/* Set the SOC revision: = (Major + 1)[11:4] | (Minor[3:0]) */
	imx_soc_revision =
		(SOC_REV_MAJOR(digprog) << 4) | SOC_REV_MINOR(digprog);
#endif
}

static uint32_t imx_soc_rev_major(void)
{
	if (imx_soc_revision < 0)
		imx_digproc();

	return imx_soc_revision >> 4;
}

uint32_t imx_soc_type(void)
{
	if (imx_cpu_type < 0)
		imx_digproc();

	return imx_cpu_type;
}

bool soc_is_imx6sl(void)
{
	return imx_soc_type() == SOC_MX6SL;
}

bool soc_is_imx6sll(void)
{
	return imx_soc_type() == SOC_MX6SLL;
}

bool soc_is_imx6sx(void)
{
	return imx_soc_type() == SOC_MX6SX;
}

bool soc_is_imx6ul(void)
{
	return imx_soc_type() == SOC_MX6UL;
}

bool soc_is_imx6ull(void)
{
	return imx_soc_type() == SOC_MX6ULL;
}

bool soc_is_imx6sdl(void)
{
	return imx_soc_type() == SOC_MX6DL;
}

bool soc_is_imx6dq(void)
{
	return (imx_soc_type() == SOC_MX6Q) && (imx_soc_rev_major() == 1);
}

bool soc_is_imx6dqp(void)
{
	return (imx_soc_type() == SOC_MX6Q) && (imx_soc_rev_major() == 2);
}

bool soc_is_imx6(void)
{
	return ((imx_soc_type() == SOC_MX6SLL) ||
		(imx_soc_type() == SOC_MX6SL) ||
		(imx_soc_type() == SOC_MX6SX) ||
		(imx_soc_type() == SOC_MX6UL) ||
		(imx_soc_type() == SOC_MX6ULL) ||
		(imx_soc_type() == SOC_MX6DL) || (imx_soc_type() == SOC_MX6Q));
}

bool soc_is_imx7ds(void)
{
	return imx_soc_type() == SOC_MX7D;
}

bool soc_is_imx7ulp(void)
{
	return imx_soc_type() == SOC_MX7ULP;
}

bool soc_is_imx8mq_b0_layer(void)
{
	if (imx_soc_type() == SOC_MX8M)
	{
		switch (imx_soc_revision)
		{
			// B0
			case 0x410:
				return true;
			default:
				break;
		}
	}
	return false;
}

uint16_t soc_revision(void)
{
	if (imx_soc_revision < 0)
		imx_digproc();

	return imx_soc_revision;
}

/*
 * Returns if the device is closed (full secure) or not
 */
bool __weak imx_is_device_closed(void)
{
	return false;
}
