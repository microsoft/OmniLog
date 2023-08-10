// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2019 NXP
 */

#include <arm.h>
#include <imx.h>
#include <imx_pm.h>
#include <io.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mmdc.h>
#include <string.h>

#define READ_DATA_FROM_HARDWARE		0

static uint32_t imx7d_ddrc_lpddr3_setting[][2] = {
	{ 0x0, READ_DATA_FROM_HARDWARE },
	{ 0x1a0, READ_DATA_FROM_HARDWARE },
	{ 0x1a4, READ_DATA_FROM_HARDWARE },
	{ 0x1a8, READ_DATA_FROM_HARDWARE },
	{ 0x64, READ_DATA_FROM_HARDWARE },
	{ 0xd0, READ_DATA_FROM_HARDWARE },
	{ 0xdc, READ_DATA_FROM_HARDWARE },
	{ 0xe0, READ_DATA_FROM_HARDWARE },
	{ 0xe4, READ_DATA_FROM_HARDWARE },
	{ 0xf4, READ_DATA_FROM_HARDWARE },
	{ 0x100, READ_DATA_FROM_HARDWARE },
	{ 0x104, READ_DATA_FROM_HARDWARE },
	{ 0x108, READ_DATA_FROM_HARDWARE },
	{ 0x10c, READ_DATA_FROM_HARDWARE },
	{ 0x110, READ_DATA_FROM_HARDWARE },
	{ 0x114, READ_DATA_FROM_HARDWARE },
	{ 0x118, READ_DATA_FROM_HARDWARE },
	{ 0x120, READ_DATA_FROM_HARDWARE },
	{ 0x11c, READ_DATA_FROM_HARDWARE },
	{ 0x180, READ_DATA_FROM_HARDWARE },
	{ 0x184, READ_DATA_FROM_HARDWARE },
	{ 0x190, READ_DATA_FROM_HARDWARE },
	{ 0x194, READ_DATA_FROM_HARDWARE },
	{ 0x200, READ_DATA_FROM_HARDWARE },
	{ 0x204, READ_DATA_FROM_HARDWARE },
	{ 0x210, READ_DATA_FROM_HARDWARE },
	{ 0x214, READ_DATA_FROM_HARDWARE },
	{ 0x218, READ_DATA_FROM_HARDWARE },
	{ 0x240, READ_DATA_FROM_HARDWARE },
	{ 0x244, READ_DATA_FROM_HARDWARE },
};

static uint32_t imx7d_ddrc_phy_lpddr3_setting[][2] = {
	{ 0x0, READ_DATA_FROM_HARDWARE },
	{ 0x4, READ_DATA_FROM_HARDWARE },
	{ 0x8, READ_DATA_FROM_HARDWARE },
	{ 0x10, READ_DATA_FROM_HARDWARE },
	{ 0xb0, READ_DATA_FROM_HARDWARE },
	{ 0x1c, READ_DATA_FROM_HARDWARE },
	{ 0x9c, READ_DATA_FROM_HARDWARE },
	{ 0x7c, READ_DATA_FROM_HARDWARE },
	{ 0x80, READ_DATA_FROM_HARDWARE },
	{ 0x84, READ_DATA_FROM_HARDWARE },
	{ 0x88, READ_DATA_FROM_HARDWARE },
	{ 0x6c, READ_DATA_FROM_HARDWARE },
	{ 0x20, READ_DATA_FROM_HARDWARE },
	{ 0x30, READ_DATA_FROM_HARDWARE },
	{ 0x50, 0x01000008 },
	{ 0x50, 0x00000008 },
	{ 0xc0, 0x0e407304 },
	{ 0xc0, 0x0e447304 },
	{ 0xc0, 0x0e447306 },
	{ 0xc0, 0x0e4c7304 },
	{ 0xc0, 0x0e487306 },
};

static uint32_t imx7d_ddrc_ddr3_setting[][2] = {
	{ 0x0, READ_DATA_FROM_HARDWARE },
	{ 0x1a0, READ_DATA_FROM_HARDWARE },
	{ 0x1a4, READ_DATA_FROM_HARDWARE },
	{ 0x1a8, READ_DATA_FROM_HARDWARE },
	{ 0x64, READ_DATA_FROM_HARDWARE },
	{ 0x490, READ_DATA_FROM_HARDWARE },
	{ 0xd0, READ_DATA_FROM_HARDWARE },
	{ 0xd4, READ_DATA_FROM_HARDWARE },
	{ 0xdc, READ_DATA_FROM_HARDWARE },
	{ 0xe0, READ_DATA_FROM_HARDWARE },
	{ 0xe4, READ_DATA_FROM_HARDWARE },
	{ 0xf4, READ_DATA_FROM_HARDWARE },
	{ 0x100, READ_DATA_FROM_HARDWARE },
	{ 0x104, READ_DATA_FROM_HARDWARE },
	{ 0x108, READ_DATA_FROM_HARDWARE },
	{ 0x10c, READ_DATA_FROM_HARDWARE },
	{ 0x110, READ_DATA_FROM_HARDWARE },
	{ 0x114, READ_DATA_FROM_HARDWARE },
	{ 0x120, READ_DATA_FROM_HARDWARE },
	{ 0x180, READ_DATA_FROM_HARDWARE },
	{ 0x190, READ_DATA_FROM_HARDWARE },
	{ 0x194, READ_DATA_FROM_HARDWARE },
	{ 0x200, READ_DATA_FROM_HARDWARE },
	{ 0x204, READ_DATA_FROM_HARDWARE },
	{ 0x214, READ_DATA_FROM_HARDWARE },
	{ 0x218, READ_DATA_FROM_HARDWARE },
	{ 0x240, READ_DATA_FROM_HARDWARE },
	{ 0x244, READ_DATA_FROM_HARDWARE },
};

static uint32_t imx7d_ddrc_phy_ddr3_setting[][2] = {
	{ 0x0, READ_DATA_FROM_HARDWARE },
	{ 0x4, READ_DATA_FROM_HARDWARE },
	{ 0x10, READ_DATA_FROM_HARDWARE },
	{ 0xb0, READ_DATA_FROM_HARDWARE },
	{ 0x9c, READ_DATA_FROM_HARDWARE },
	{ 0x7c, READ_DATA_FROM_HARDWARE },
	{ 0x80, READ_DATA_FROM_HARDWARE },
	{ 0x84, READ_DATA_FROM_HARDWARE },
	{ 0x88, READ_DATA_FROM_HARDWARE },
	{ 0x6c, READ_DATA_FROM_HARDWARE },
	{ 0x20, READ_DATA_FROM_HARDWARE },
	{ 0x30, READ_DATA_FROM_HARDWARE },
	{ 0x50, 0x01000010 },
	{ 0x50, 0x00000010 },
	{ 0xc0, 0x0e407304 },
	{ 0xc0, 0x0e447304 },
	{ 0xc0, 0x0e447306 },
	{ 0xc0, 0x0e447304 },
	{ 0xc0, 0x0e407306 },
};

static struct imx7_pm_data imx7d_pm_data_lpddr3 = {
	.ddrc_num = ARRAY_SIZE(imx7d_ddrc_lpddr3_setting),
	.ddrc_offset = imx7d_ddrc_lpddr3_setting,
	.ddrc_phy_num = ARRAY_SIZE(imx7d_ddrc_phy_lpddr3_setting),
	.ddrc_phy_offset = imx7d_ddrc_phy_lpddr3_setting,
};

static struct imx7_pm_data imx7d_pm_data_ddr3 = {
	.ddrc_num = ARRAY_SIZE(imx7d_ddrc_ddr3_setting),
	.ddrc_offset = imx7d_ddrc_ddr3_setting,
	.ddrc_phy_num = ARRAY_SIZE(imx7d_ddrc_phy_ddr3_setting),
	.ddrc_phy_offset = imx7d_ddrc_phy_ddr3_setting,
};

struct imx7_pm_info *pm_info;

int imx7_suspend_init(void)
{
	uint32_t i;
	uint32_t (*ddrc_offset_array)[2];
	uint32_t (*ddrc_phy_offset_array)[2];
	uint32_t suspend_ocram_base = core_mmu_get_va(
						imx_get_ocram_tz_start_addr() +
						SUSPEND_OCRAM_OFFSET,
							MEM_AREA_TEE_COHERENT);
	struct imx7_pm_info *p = (struct imx7_pm_info *)suspend_ocram_base;
	struct imx7_pm_data *pm_data;

	pm_info = p;

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

	DMSG("%x %x\n", suspend_ocram_base, sizeof(*p));

	p->pa_base = imx_get_ocram_tz_start_addr() + SUSPEND_OCRAM_OFFSET;
	p->tee_resume = virt_to_phys((void *)(vaddr_t)ca7_cpu_resume);
	p->pm_info_size = sizeof(*p);
	p->ccm_va_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	p->ccm_pa_base = CCM_BASE;
	p->ddrc_va_base = core_mmu_get_va(DDRC_BASE, MEM_AREA_IO_SEC);
	p->ddrc_pa_base = DDRC_BASE;
	p->ddrc_phy_va_base = core_mmu_get_va(DDRC_PHY_BASE, MEM_AREA_IO_SEC);
	p->ddrc_phy_pa_base = DDRC_PHY_BASE;
	p->src_va_base = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);
	p->src_pa_base = SRC_BASE;
	p->iomuxc_gpr_va_base = core_mmu_get_va(IOMUXC_GPR_BASE,
						MEM_AREA_IO_SEC);
	p->iomuxc_gpr_pa_base = IOMUXC_GPR_BASE;
	p->gpc_va_base = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC);
	p->gpc_pa_base = GPC_BASE;
	p->anatop_va_base = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);
	p->anatop_pa_base = ANATOP_BASE;
	p->snvs_va_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);
	p->snvs_pa_base = SNVS_BASE;
	p->lpsr_va_base = core_mmu_get_va(LPSR_BASE, MEM_AREA_IO_SEC);
	p->lpsr_pa_base = LPSR_BASE;
	p->gic_va_base = core_mmu_get_va(GIC_BASE, MEM_AREA_IO_SEC);
	p->gic_pa_base = GIC_BASE;

	/* TODO:lpsr disabled now */
	io_write32(p->lpsr_va_base, 0);

	p->ddr_type = imx_get_ddr_type();
	switch (p->ddr_type) {
	case IMX_DDR_TYPE_DDR3:
		pm_data = &imx7d_pm_data_ddr3;
		break;
	case IMX_DDR_TYPE_LPDDR3:
		pm_data = &imx7d_pm_data_lpddr3;
		break;
	default:
		panic("Not supported ddr type\n");
		break;
	}

	p->ddrc_num = pm_data->ddrc_num;
	p->ddrc_phy_num = pm_data->ddrc_phy_num;
	ddrc_offset_array = pm_data->ddrc_offset;
	ddrc_phy_offset_array = pm_data->ddrc_phy_offset;

	for (i = 0; i < p->ddrc_num; i++) {
		p->ddrc_val[i][0] = ddrc_offset_array[i][0];
		if (ddrc_offset_array[i][1] == READ_DATA_FROM_HARDWARE)
			p->ddrc_val[i][1] = io_read32(p->ddrc_va_base +
						      ddrc_offset_array[i][0]);
		else
			p->ddrc_val[i][1] = ddrc_offset_array[i][1];

		if (p->ddrc_val[i][0] == 0xd0)
			p->ddrc_val[i][1] |= 0xc0000000;
	}

	/* initialize DDRC PHY settings */
	for (i = 0; i < p->ddrc_phy_num; i++) {
		p->ddrc_phy_val[i][0] = ddrc_phy_offset_array[i][0];
		if (ddrc_phy_offset_array[i][1] == READ_DATA_FROM_HARDWARE)
			p->ddrc_phy_val[i][1] =
				io_read32(p->ddrc_phy_va_base +
					  ddrc_phy_offset_array[i][0]);
		else
			p->ddrc_phy_val[i][1] = ddrc_phy_offset_array[i][1];
	}

	memcpy((void *)(suspend_ocram_base + sizeof(*p)),
	       (void *)(vaddr_t)imx7_suspend, SUSPEND_OCRAM_SIZE - sizeof(*p));

	dcache_clean_range((void *)suspend_ocram_base, SUSPEND_OCRAM_SIZE);

	/*
	 * Note that IRAM IOSEC map, if changed to MEM map,
	 * need to flush cache
	 */
	icache_inv_all();

	return 0;
}
