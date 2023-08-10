// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
#include <imx.h>
#include <imx_pm.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mmdc.h>
#include <string.h>

const uint32_t imx6q_mmdc_io_offset[] = {
	0x5ac, 0x5b4, 0x528, 0x520, /* DQM0 ~ DQM3 */
	0x514, 0x510, 0x5bc, 0x5c4, /* DQM4 ~ DQM7 */
	0x56c, 0x578, 0x588, 0x594, /* CAS, RAS, SDCLK_0, SDCLK_1 */
	0x5a8, 0x5b0, 0x524, 0x51c, /* SDQS0 ~ SDQS3 */
	0x518, 0x50c, 0x5b8, 0x5c0, /* SDQS4 ~ SDQS7 */
	0x784, 0x788, 0x794, 0x79c, /* GPR_B0DS ~ GPR_B3DS */
	0x7a0, 0x7a4, 0x7a8, 0x748, /* GPR_B4DS ~ GPR_B7DS */
	0x59c, 0x5a0, 0x750, 0x774, /* SODT0, SODT1, MODE_CTL, MODE */
	0x74c,                      /* GPR_ADDS */
};

const uint32_t imx6dl_mmdc_io_offset[] = {
	0x470, 0x474, 0x478, 0x47c, /* DQM0 ~ DQM3 */
	0x480, 0x484, 0x488, 0x48c, /* DQM4 ~ DQM7 */
	0x464, 0x490, 0x4ac, 0x4b0, /* CAS, RAS, SDCLK_0, SDCLK_1 */
	0x4bc, 0x4c0, 0x4c4, 0x4c8, /* DRAM_SDQS0 ~ DRAM_SDQS3 */
	0x4cc, 0x4d0, 0x4d4, 0x4d8, /* DRAM_SDQS4 ~ DRAM_SDQS7 */
	0x764, 0x770, 0x778, 0x77c, /* GPR_B0DS ~ GPR_B3DS */
	0x780, 0x784, 0x78c, 0x748, /* GPR_B4DS ~ GPR_B7DS */
	0x4b4, 0x4b8, 0x750, 0x760, /* SODT0, SODT1, MODE_CTL, MODE */
	0x74c,                      /* GPR_ADDS */
};

const uint32_t imx6ul_mmdc_io_offset[] = {
	0x244, 0x248, 0x24c, 0x250, /* DQM0, DQM1, RAS, CAS */
	0x27c, 0x498, 0x4a4, 0x490, /* SDCLK0, GPR_B0DS-B1DS, GPR_ADDS */
	0x280, 0x284, 0x260, 0x264, /* SDQS0~1, SODT0, SODT1 */
	0x494, 0x4b0,               /* MODE_CTL, MODE, */
};

const uint32_t imx6ul_mmdc_offset[] = {
	0x01c, 0x800, 0x80c, 0x83c,
	0x848, 0x850, 0x81c, 0x820,
	0x82c, 0x830, 0x8c0, 0x8b8,
	0x004, 0x008, 0x00c, 0x010,
	0x014, 0x018, 0x01c, 0x02c,
	0x030, 0x040, 0x000, 0x01c,
	0x020, 0x818, 0x01c,
};

const uint32_t imx6ul_mmdc_io_lpddr2_offset[] = {
	0x244, 0x248, 0x24c, 0x250,	/* DQM0, DQM1, RAS, CAS */
	0x27c, 0x498, 0x4a4, 0x490,	/* SDCLK0, GPR_B0DS-B1DS, GPR_ADDS */
	0x280, 0x284, 0x260, 0x264,	/* SDQS0~1, SODT0, SODT1 */
	0x494, 0x4b0, 0x274, 0x278,	/* MODE_CTL, MODE, SDCKE0, SDCKE1 */
	0x288,				/* DRAM_RESET */
};

const uint32_t imx6ul_mmdc_lpddr2_offset[] = {
	0x01c, 0x85c, 0x800, 0x890,
	0x8b8, 0x81c, 0x820, 0x82c,
	0x830, 0x83c, 0x848, 0x850,
	0x8c0, 0x8b8, 0x004, 0x008,
	0x00c, 0x010, 0x038, 0x014,
	0x018, 0x01c, 0x02c, 0x030,
	0x040, 0x000, 0x020, 0x818,
	0x800, 0x004, 0x01c,
};

const uint32_t imx6sx_mmdc_io_offset[] = {
	0x2ec, 0x2f0, 0x2f4, 0x2f8,
	0x60c, 0x610, 0x61c, 0x620,
	0x300, 0x2fc, 0x32c, 0x5f4,
	0x310, 0x314, 0x5f8, 0x608,
	0x330, 0x334, 0x338, 0x33c,
};

const uint32_t imx6sx_mmdc_offset[] = {
	0x800, 0x80c, 0x810, 0x83c,
	0x840, 0x848, 0x850, 0x81c,
	0x820, 0x824, 0x828, 0x8b8,
	0x004, 0x008, 0x00c, 0x010,
	0x014, 0x018, 0x01c, 0x02c,
	0x030, 0x040, 0x000, 0x01c,
	0x020, 0x818, 0x01c,
};

const uint32_t imx6sx_mmdc_io_lpddr2_offset[] = {
	0x2ec, 0x2f0, 0x2f4, 0x2f8,
	0x300, 0x2fc, 0x32c, 0x5f4,
	0x60c, 0x610, 0x61c, 0x620,
	0x310, 0x314, 0x5f8, 0x608,
	0x330, 0x334, 0x338, 0x33c,
	0x324, 0x328, 0x340,
};

const uint32_t imx6sx_mmdc_lpddr2_offset[] = {
	0x01c, 0x85c, 0x800, 0x890,
	0x8b8, 0x81c, 0x820, 0x824,
	0x828, 0x82c, 0x830, 0x834,
	0x838, 0x848, 0x850, 0x8c0,
	0x83c, 0x840, 0x8b8, 0x00c,
	0x004, 0x010, 0x014, 0x018,
	0x02c, 0x030, 0x038, 0x008,
	0x040, 0x000, 0x020, 0x818,
	0x800, 0x004, 0x01c,
};

const uint32_t imx6sl_mmdc_io_offset[] = {
	0x30c, 0x310, 0x314, 0x318, /* DQM0 ~ DQM3 */
	0x5c4, 0x5cc, 0x5d4, 0x5d8, /* GPR_B0DS ~ GPR_B3DS */
	0x300, 0x31c, 0x338, 0x5ac, /* CAS, RAS, SDCLK_0, GPR_ADDS */
	0x33c, 0x340, 0x5b0, 0x5c0, /* SODT0, SODT1, MODE_CTL, MODE */
	0x330, 0x334, 0x320,        /* SDCKE0, SDCKE1, RESET */
};

const uint32_t imx6sll_mmdc_io_offset[] = {
	0x294, 0x298, 0x29c, 0x2a0, /* DQM0 ~ DQM3 */
	0x544, 0x54c, 0x554, 0x558, /* GPR_B0DS ~ GPR_B3DS */
	0x530, 0x540, 0x2ac, 0x52c, /* MODE_CTL, MODE, SDCLK_0, GPR_ADDDS */
	0x2a4, 0x2a8,               /* SDCKE0, SDCKE1*/
};

const uint32_t imx6sll_mmdc_lpddr3_offset[] = {
	0x01c, 0x85c, 0x800, 0x890,
	0x8b8, 0x81c, 0x820, 0x82c,
	0x830, 0x83c, 0x848, 0x850,
	0x8c0, 0x8b8, 0x004, 0x008,
	0x00c, 0x010, 0x038, 0x014,
	0x018, 0x01c, 0x02c, 0x030,
	0x040, 0x000, 0x020, 0x818,
	0x800, 0x004, 0x01c,
};

static struct imx6_pm_data imx6q_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6q_mmdc_io_offset),
	.mmdc_io_offset = imx6q_mmdc_io_offset,
	.mmdc_num = 0,
	.mmdc_offset = NULL,
};

static struct imx6_pm_data imx6dl_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6dl_mmdc_io_offset),
	.mmdc_io_offset = imx6dl_mmdc_io_offset,
	.mmdc_num = 0,
	.mmdc_offset = NULL,
};

struct imx6_pm_data imx6ul_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6ul_mmdc_io_offset),
	.mmdc_io_offset = imx6ul_mmdc_io_offset,
	.mmdc_num = ARRAY_SIZE(imx6ul_mmdc_offset),
	.mmdc_offset = imx6ul_mmdc_offset,
};

static struct imx6_pm_data imx6ul_lpddr2_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6ul_mmdc_io_lpddr2_offset),
	.mmdc_io_offset = imx6ul_mmdc_io_lpddr2_offset,
	.mmdc_num = ARRAY_SIZE(imx6ul_mmdc_lpddr2_offset),
	.mmdc_offset = imx6ul_mmdc_lpddr2_offset,
};

struct imx6_pm_data imx6sx_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6sx_mmdc_io_offset),
	.mmdc_io_offset = imx6sx_mmdc_io_offset,
	.mmdc_num = ARRAY_SIZE(imx6sx_mmdc_offset),
	.mmdc_offset = imx6sx_mmdc_offset,
};

static struct imx6_pm_data imx6sx_lpddr2_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6sx_mmdc_io_lpddr2_offset),
	.mmdc_io_offset = imx6sx_mmdc_io_lpddr2_offset,
	.mmdc_num = ARRAY_SIZE(imx6sx_mmdc_lpddr2_offset),
	.mmdc_offset = imx6sx_mmdc_lpddr2_offset,
};

struct imx6_pm_data imx6sl_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6sl_mmdc_io_offset),
	.mmdc_io_offset = imx6sl_mmdc_io_offset,
	.mmdc_num = 0,
	.mmdc_offset = NULL,
};

struct imx6_pm_data imx6sll_pm_data = {
	.mmdc_io_num = ARRAY_SIZE(imx6sll_mmdc_io_offset),
	.mmdc_io_offset = imx6sll_mmdc_io_offset,
	.mmdc_num = ARRAY_SIZE(imx6sll_mmdc_lpddr3_offset),
	.mmdc_offset = imx6sll_mmdc_lpddr3_offset,
};

/**
 * @brief   PM OCRAM free area start address
 */
vaddr_t pm_ocram_free_area;

int imx6_suspend_init(void)
{
	uint32_t i;
	const uint32_t *mmdc_offset_array;
	const uint32_t *mmdc_io_offset_array;
	struct imx6_pm_data *pm_data;

	uint32_t suspend_ocram_base = core_mmu_get_va(
					imx_get_ocram_tz_start_addr() +
					SUSPEND_OCRAM_OFFSET,
						MEM_AREA_TEE_COHERENT);
	struct imx6_pm_info *p = (struct imx6_pm_info *)suspend_ocram_base;

	uint32_t func_size = get_imx6_suspend_size();

	suspend_func = (int (*)(uint32_t))(suspend_ocram_base + sizeof(*p));

	suspend_arg.pa_addr = virt_to_phys((void *)(vaddr_t)suspend_func);
	suspend_arg.pm_info = p;

	p->pa_base =  imx_get_ocram_tz_start_addr() + SUSPEND_OCRAM_OFFSET;
	p->tee_resume = (paddr_t)virt_to_phys((void *)(vaddr_t)v7_cpu_resume);
	p->ccm_va_base = core_mmu_get_va(CCM_BASE, MEM_AREA_IO_SEC);
	p->ccm_pa_base = CCM_BASE;
	p->mmdc0_va_base = core_mmu_get_va(MMDC_P0_BASE, MEM_AREA_IO_SEC);
	p->mmdc0_pa_base = MMDC_P0_BASE;
#if !(defined(CFG_MX6UL) || defined(CFG_MX6ULL) || \
	defined(CFG_MX6SL) || defined(CFG_MX6SLL))
	p->mmdc1_va_base = core_mmu_get_va(MMDC_P1_BASE, MEM_AREA_IO_SEC);
	p->mmdc1_pa_base = MMDC_P1_BASE;
#endif
	p->src_va_base = core_mmu_get_va(SRC_BASE, MEM_AREA_IO_SEC);
	p->src_pa_base = SRC_BASE;
	p->iomuxc_va_base = core_mmu_get_va(IOMUXC_BASE, MEM_AREA_IO_SEC);
	p->iomuxc_pa_base = IOMUXC_BASE;
	p->gpc_va_base = core_mmu_get_va(GPC_BASE, MEM_AREA_IO_SEC);
	p->gpc_pa_base = GPC_BASE;
#ifdef CFG_PL310
	p->pl310_va_base = core_mmu_get_va(PL310_BASE, MEM_AREA_IO_SEC);
#endif
	p->anatop_va_base = core_mmu_get_va(ANATOP_BASE, MEM_AREA_IO_SEC);
	p->anatop_pa_base = ANATOP_BASE;

	if (soc_is_imx6sx()) {
		p->sema4_pa_base = SEMA4_BASE;
		p->sema4_va_base = core_mmu_get_va(SEMA4_BASE, MEM_AREA_IO_SEC);
	}

	p->ddr_type = imx_get_ddr_type();
	switch (p->ddr_type) {
	case IMX_DDR_TYPE_DDR3:
		if (soc_is_imx6dq() || soc_is_imx6dqp())
			pm_data = &imx6q_pm_data;
		else if (soc_is_imx6sdl())
			pm_data = &imx6dl_pm_data;
		else if (soc_is_imx6ul() || soc_is_imx6ull())
			pm_data = &imx6ul_pm_data;
		else if (soc_is_imx6sx())
			pm_data = &imx6sx_pm_data;
		else
			panic("Not supported\n");

		break;
	case IMX_DDR_TYPE_LPDDR2:
		if (soc_is_imx6ul() || soc_is_imx6ull())
			pm_data = &imx6ul_lpddr2_pm_data;
		else if (soc_is_imx6sl())
			pm_data = &imx6sl_pm_data;
		else if (soc_is_imx6sx())
			pm_data = &imx6sx_lpddr2_pm_data;
		else
			panic("No lpddr2 support\n");
		break;

	case IMX_MMDC_DDR_TYPE_LPDDR3:
		pm_data = &imx6sll_pm_data;
		break;
	default:
		panic("Not supported ddr type\n");
		break;
	}

	p->mmdc_io_num = pm_data->mmdc_io_num;
	p->mmdc_num = pm_data->mmdc_num;
	mmdc_io_offset_array = pm_data->mmdc_io_offset;
	mmdc_offset_array = pm_data->mmdc_offset;

	for (i = 0; i < p->mmdc_io_num; i++) {
		p->mmdc_io_val[i][0] = mmdc_io_offset_array[i];
		/* Not sure why read32 will complain readelf warning */
		p->mmdc_io_val[i][1] = io_read32(p->iomuxc_va_base +
					mmdc_io_offset_array[i]);
		p->mmdc_io_val[i][2] = 0;
	}

	/* There is no DRAM RESET pin on i.MX6SLL */
	if (soc_is_imx6sll()) {
		p->mmdc_io_val[p->mmdc_io_num - 2][2] = 0x1000;
		p->mmdc_io_val[p->mmdc_io_num - 1][2] = 0x1000;
	} else {
		if (p->ddr_type == IMX_DDR_TYPE_LPDDR2) {
		/* For LPDDR2, CKE0/1 and RESET pin need special setting */
			p->mmdc_io_val[p->mmdc_io_num - 3][2] = 0x1000;
			p->mmdc_io_val[p->mmdc_io_num - 2][2] = 0x1000;
			p->mmdc_io_val[p->mmdc_io_num - 1][2] = 0x1000;
		}
	}

	for (i = 0; i < p->mmdc_num; i++) {
		p->mmdc_val[i][0] = mmdc_offset_array[i];
		p->mmdc_val[i][1] = io_read32(p->mmdc0_va_base +
					mmdc_offset_array[i]);
	}

	if (soc_is_imx6sll() && p->ddr_type == IMX_MMDC_DDR_TYPE_LPDDR3) {
		p->mmdc_val[0][1] = 0x8000;
		p->mmdc_val[2][1] = 0xa1390003;
		p->mmdc_val[3][1] = 0x400000;
		p->mmdc_val[4][1] = 0x800;
		p->mmdc_val[13][1] = 0x800;
		p->mmdc_val[14][1] = 0x20052;
		p->mmdc_val[20][1] = 0x201718;
		p->mmdc_val[21][1] = 0x8000;
		p->mmdc_val[28][1] = 0xa1310003;
	}

	if ((soc_is_imx6sx() || soc_is_imx6ul() || soc_is_imx6ull()) &&
	    p->ddr_type != IMX_DDR_TYPE_LPDDR2) {
		p->mmdc_val[20][1] = (p->mmdc_val[20][1] &
				      0xffff0000) | 0x0202;
		p->mmdc_val[23][1] = 0x8033;
	}

	if (soc_is_imx6sx() && p->ddr_type == IMX_DDR_TYPE_LPDDR2) {
		p->mmdc_val[0][1] = 0x8000;
		p->mmdc_val[2][1] = 0xa1390003;
		p->mmdc_val[3][1] = 0x380000;
		p->mmdc_val[4][1] = 0x800;
		p->mmdc_val[18][1] = 0x800;
		p->mmdc_val[20][1] = 0x20024;
		p->mmdc_val[23][1] = 0x1748;
		p->mmdc_val[32][1] = 0xa1310003;
	}

	if ((soc_is_imx6ul() || soc_is_imx6ull()) &&
	    p->ddr_type == IMX_DDR_TYPE_LPDDR2) {
		p->mmdc_val[0][1] = 0x8000;
		p->mmdc_val[2][1] = 0xa1390003;
		p->mmdc_val[3][1] = 0x470000;
		p->mmdc_val[4][1] = 0x800;
		p->mmdc_val[13][1] = 0x800;
		p->mmdc_val[14][1] = 0x20012;
		p->mmdc_val[20][1] = 0x1748;
		p->mmdc_val[21][1] = 0x8000;
		p->mmdc_val[28][1] = 0xa1310003;
	}

	memcpy((void *)(vaddr_t)suspend_func,
			(void *)(vaddr_t)imx6_suspend, func_size);

	pm_ocram_free_area = (vaddr_t)suspend_func + func_size;

	dcache_clean_range((void *)suspend_ocram_base,
			(pm_ocram_free_area - suspend_ocram_base + 4));
	/* Note that IRAM IOSEC map, if changed to MEM map,
	 * need to flush cache
	 */
	icache_inv_all();

	return 0;
}
