// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
#include <imx_pm.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>

static uint32_t imx7ulp_mmdc_io_lpddr3_offset[] = {
	0x128, 0xf8, 0xd8, 0x108,
	0x104, 0x124, 0x80, 0x84,
	0x88, 0x8c, 0x120, 0x10c,
	0x110, 0x114, 0x118, 0x90,
	0x94, 0x98, 0x9c, 0xe0,
	0xe4,
};

static uint32_t imx7ulp_mmdc_lpddr3_offset[] = {
	0x01c, 0x800, 0x85c, 0x890,
	0x848, 0x850, 0x81c, 0x820,
	0x824, 0x828, 0x82c, 0x830,
	0x834, 0x838, 0x8c0, 0x8b8,
	0x004, 0x00c, 0x010, 0x038,
	0x014, 0x018, 0x02c, 0x030,
	0x040, 0x000, 0x01c, 0x01c,
	0x01c, 0x01c, 0x01c, 0x01c,
	0x01c, 0x01c, 0x01c, 0x01c,
	0x01c, 0x01c, 0x83c, 0x020,
	0x800, 0x004, 0x404, 0x01c,
};

static const uint32_t imx7ulp_lpddr3_script[] = {
	0x00008000, 0xA1390003, 0x0D3900A0, 0x00400000,
	0x40404040, 0x40404040, 0x33333333, 0x33333333,
	0x33333333, 0x33333333, 0xf3333333, 0xf3333333,
	0xf3333333, 0xf3333333, 0x24922492, 0x00000800,
	0x00020052, 0x292C42F3, 0x00100A22, 0x00120556,
	0x00C700DB, 0x00211718, 0x0F9F26D2, 0x009F0E10,
	0x0000003F, 0xC3190000, 0x00008050, 0x00008058,
	0x003F8030, 0x003F8038, 0xFF0A8030, 0xFF0A8038,
	0x04028030, 0x04028038, 0x83018030, 0x83018038,
	0x01038030, 0x01038038, 0x20000000, 0x00001800,
	0xA1310000, 0x00020052, 0x00011006, 0x00000000,
};

static struct imx7ulp_pm_data imx7ulp_lpddr3_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx7ulp_mmdc_io_lpddr3_offset),
	.mmdc_io_offset = imx7ulp_mmdc_io_lpddr3_offset,
	.mmdc_num = ARRAY_SIZE(imx7ulp_mmdc_lpddr3_offset),
	.mmdc_offset = imx7ulp_mmdc_lpddr3_offset,
};

struct imx7ulp_pm_info *pm_info;

int imx7ulp_suspend_init(void)
{
	uint32_t i;
	uint32_t suspend_ocram_base = (uint32_t)core_mmu_get_va(
			(paddr_t)LP_OCRAM_START +
			SUSPEND_OCRAM_OFFSET, MEM_AREA_TEE_COHERENT);
	struct imx7ulp_pm_info *p =
			(struct imx7ulp_pm_info *)suspend_ocram_base;
	struct imx7ulp_pm_data *pm_data;
	uint32_t *mmdc_io_offset_array, *mmdc_offset_array;

	pm_info = p;

	dcache_op_level1(DCACHE_OP_CLEAN_INV);

	DMSG("%x %x\n", suspend_ocram_base, sizeof(*p));

	p->pbase = LP_OCRAM_START + SUSPEND_OCRAM_OFFSET;
	p->resume_addr = (paddr_t)virt_to_phys(
				(void *)(vaddr_t)imx7ulp_cpu_resume);
	p->pm_info_size = sizeof(*p);
	p->scg1_base = core_mmu_get_va(SCG1_BASE, MEM_AREA_IO_SEC);
	p->smc1_base = core_mmu_get_va(SMC1_BASE, MEM_AREA_IO_SEC);
	p->mmdc_base = core_mmu_get_va(MMDC_BASE, MEM_AREA_IO_SEC);
	p->mmdc_io_base = core_mmu_get_va(MMDC_IO_BASE, MEM_AREA_IO_SEC);
	p->sim_base = core_mmu_get_va(SIM_BASE, MEM_AREA_IO_SEC);

	pm_data = &imx7ulp_lpddr3_pm_data;
	p->mmdc_io_num = pm_data->mmdc_io_num;
	mmdc_io_offset_array = pm_data->mmdc_io_offset;
	p->mmdc_num = pm_data->mmdc_num;
	mmdc_offset_array = pm_data->mmdc_offset;

	for (i = 0; i < p->mmdc_io_num; i++) {
		p->mmdc_io_val[i][0] = mmdc_io_offset_array[i];
		p->mmdc_io_val[i][1] = io_read32(p->mmdc_io_base +
					      mmdc_io_offset_array[i]);
	}

	/* initialize MMDC settings */
	for (i = 0; i < p->mmdc_num; i++)
		p->mmdc_val[i][0] = mmdc_offset_array[i];

	for (i = 0; i < p->mmdc_num; i++)
		p->mmdc_val[i][1] = imx7ulp_lpddr3_script[i];

	memcpy((void *)(suspend_ocram_base + sizeof(*p)),
			(void *)(vaddr_t)imx7ulp_suspend,
			SUSPEND_OCRAM_SIZE - sizeof(*p));

	dcache_clean_range((void *)suspend_ocram_base, SUSPEND_OCRAM_SIZE);
	/* Note that IRAM IOSEC map,
	 * if changed to MEM map, need to flush cache
	 */
	icache_inv_all();

	DMSG("%s %x\n", __func__, (uint32_t)(p->resume_addr));

	return 0;
}
