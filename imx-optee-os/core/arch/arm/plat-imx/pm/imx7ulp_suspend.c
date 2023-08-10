// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */
#include <arm.h>
#include <console.h>
#include <io.h>
#include <imx_pm.h>
#include <imx.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/sm.h>
#include <sm/pm.h>

/*
 * TODO:
 * Suspend/resume and low power idle share this,
 * But do we need to provide different ones for them?
 */

static int suspended_init;
static vaddr_t gpio_base[4];
static vaddr_t scg1_base;
static vaddr_t pcc2_base;
static vaddr_t pcc3_base;
static vaddr_t iomuxc1_base;
static vaddr_t tpm5_base;
static vaddr_t smc1_base;
static vaddr_t pmc0_base;
static vaddr_t pmc1_base;

#define GPIO_PDOR	0x0
#define GPIO_PDDR	0x14

#define IOMUX_START		0x0
#define SELECT_INPUT_START	0x200

#define DGO_GPR3	0x60
#define DGO_GPR4	0x64

#define TPM_SC		0x10
#define TPM_MOD		0x18
#define TPM_C0SC	0x20
#define TPM_C0V		0x24

#define PMPROT	0x8
#define PMCTRL	0x10
#define PMSTAT	0x18
#define SRS	0x20
#define RPC	0x24
#define SSRS	0x28
#define SRIE	0x2c
#define SRIF	0x30
#define CSRE	0x34
#define MR	0x40

#define PMC_HSRUN		0x4
#define PMC_RUN			0x8
#define PMC_VLPR		0xc
#define PMC_STOP		0x10
#define PMC_VLPS		0x14
#define PMC_LLS			0x18
#define PMC_VLLS		0x1c
#define PMC_STATUS		0x20
#define PMC_CTRL		0x24
#define PMC_SRAMCTRL_0		0x28
#define PMC_SRAMCTRL_1		0x2c
#define PMC_SRAMCTRL_2		0x30

#define BM_PMPROT_AHSRUN	SHIFT_U32(1, 7)
#define BM_PMPROT_AVLP		SHIFT_U32(1, 5)
#define BM_PMPROT_ALLS		SHIFT_U32(1, 3)
#define BM_PMPROT_AVLLS		SHIFT_U32(1, 1)

#define BM_PMCTRL_STOPA		SHIFT_U32(1, 24)
#define BM_PMCTRL_PSTOPO	SHIFT_U32(3, 16)
#define BM_PMCTRL_RUNM		SHIFT_U32(3, 8)
#define BM_PMCTRL_STOPM		SHIFT_U32(7, 0)

#define BM_VLPS_RBBEN		SHIFT_U32(1, 28)

#define BM_CTRL_LDOEN		SHIFT_U32(1, 31)
#define BM_CTRL_LDOOKDIS	SHIFT_U32(1, 30)

#define BM_VLLS_MON1P2HVDHP	SHIFT_U32(1, 5)
#define BM_VLLS_MON1P2LVDHP	SHIFT_U32(1, 4)

#define BP_PMCTRL_STOPM		0
#define BP_PMCTRL_PSTOPO	16

static uint32_t tpm5_regs[4];
static uint32_t pcc2_regs[][2] = {
	{0x20, 0}, {0x3c, 0}, {0x40, 0}, {0x6c, 0},
	{0x84, 0}, {0x90, 0}, {0x94, 0}, {0x98, 0},
	{0x9c, 0}, {0xa4, 0}, {0xa8, 0}, {0xac, 0},
	{0xb0, 0}, {0xb4, 0}, {0xb8, 0}, {0xc4, 0},
	{0xcc, 0}, {0xd0, 0}, {0xd4, 0}, {0xd8, 0},
	{0xdc, 0}, {0xe0, 0}, {0xf4, 0}, {0x10c, 0},
};

static uint32_t pcc3_regs[][2] = {
	{0x84, 0}, {0x88, 0}, {0x90, 0}, {0x94, 0},
	{0x98, 0}, {0x9c, 0}, {0xa0, 0}, {0xa4, 0},
	{0xa8, 0}, {0xac, 0}, {0xb8, 0}, {0xbc, 0},
	{0xc0, 0}, {0xc4, 0}, {0x140, 0}, {0x144, 0},
};

static uint32_t scg1_offset[] = {
	0x14, 0x30, 0x40, 0x304,
	0x500, 0x504, 0x508, 0x50c,
	0x510, 0x514, 0x600, 0x604,
	0x608, 0x60c, 0x610, 0x614,
	0x104,
};


static void imx7ulp_gpio_save(struct imx7ulp_pm_info *p)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(gpio_base); i++) {
		p->gpio[i][0] = io_read32(gpio_base[i] + GPIO_PDOR);
		p->gpio[i][1] = io_read32(gpio_base[i] + GPIO_PDDR);
	}
}

static void imx7ulp_scg1_save(struct imx7ulp_pm_info *p)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(scg1_offset); i++)
		p->scg1[i] = io_read32(scg1_base + scg1_offset[i]);
}

static void imx7ulp_pcc3_save(struct imx7ulp_pm_info *p __unused)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(pcc3_regs); i++)
		pcc3_regs[i][1] = io_read32(pcc3_base + pcc3_regs[i][0]);
}

static void imx7ulp_pcc3_restore(struct imx7ulp_pm_info *p __unused)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(pcc3_regs); i++)
		io_write32(pcc3_base + pcc3_regs[i][0], pcc3_regs[i][1]);
}

static void imx7ulp_pcc2_save(struct imx7ulp_pm_info *p __unused)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(pcc2_regs); i++)
		pcc2_regs[i][1] = io_read32(pcc2_base + pcc2_regs[i][0]);
}

static void imx7ulp_pcc2_restore(struct imx7ulp_pm_info *p __unused)
{
	uint32_t i;

	for (i = 0; i < ARRAY_SIZE(pcc2_regs); i++)
		io_write32(pcc2_base + pcc2_regs[i][0], pcc2_regs[i][1]);
}

static inline void imx7ulp_iomuxc_save(struct imx7ulp_pm_info *p)
{
	uint32_t i;

	p->iomux_num = MX7ULP_MAX_IOMUX_NUM;
	p->select_input_num = MX7ULP_MAX_SELECT_INPUT_NUM;

	for (i = 0; i < p->iomux_num; i++)
		p->iomux_val[i] = io_read32(iomuxc1_base + IOMUX_START + i * 0x4);
	for (i = 0; i < p->select_input_num; i++)
		p->select_input_val[i] = io_read32(iomuxc1_base +
						SELECT_INPUT_START + i * 0x4);
}

static void imx7ulp_tpm_save(struct imx7ulp_pm_info *p __unused)
{
	tpm5_regs[0] = io_read32(tpm5_base + TPM_SC);
	tpm5_regs[1] = io_read32(tpm5_base + TPM_MOD);
	tpm5_regs[2] = io_read32(tpm5_base + TPM_C0SC);
	tpm5_regs[3] = io_read32(tpm5_base + TPM_C0V);
}

static void imx7ulp_tpm_restore(struct imx7ulp_pm_info *p __unused)
{
	io_write32(tpm5_base + TPM_SC, tpm5_regs[0]);
	io_write32(tpm5_base + TPM_MOD, tpm5_regs[1]);
	io_write32(tpm5_base + TPM_C0SC, tpm5_regs[2]);
	io_write32(tpm5_base + TPM_C0V, tpm5_regs[3]);
}

static void imx7ulp_set_dgo(struct imx7ulp_pm_info *p, uint32_t val)
{
	io_write32(p->sim_base + DGO_GPR3, val);
	io_write32(p->sim_base + DGO_GPR4, val);
}

static int imx7ulp_set_lpm(enum imx7ulp_sys_pwr_mode mode)
{
	uint32_t val1 = BM_PMPROT_AHSRUN | BM_PMPROT_AVLP | BM_PMPROT_AVLLS;
	uint32_t val2 = io_read32(smc1_base + PMCTRL);
	uint32_t val3 = io_read32(pmc0_base + PMC_CTRL);

	val2 &= ~(BM_PMCTRL_RUNM |
		BM_PMCTRL_STOPM | BM_PMCTRL_PSTOPO);
	val3 |= BM_CTRL_LDOOKDIS;

	switch (mode) {
	case RUN:
		/* system/bus clock enabled */
		val2 |= 0x3 << BP_PMCTRL_PSTOPO;
		break;
	case WAIT:
		/* system clock disabled, bus clock enabled */
		val2 |= 0x2 << BP_PMCTRL_PSTOPO;
		break;
	case STOP:
		/* system/bus clock disabled */
		val2 |= 0x1 << BP_PMCTRL_PSTOPO;
		break;
	case VLPS:
		val2 |= 0x2 << BP_PMCTRL_STOPM;
		break;
	case VLLS:
		val2 |= 0x4 << BP_PMCTRL_STOPM;
		break;
	default:
		panic("Not correct lpm mode\n");
	}

	io_write32(smc1_base + PMPROT, val1);
	io_write32(smc1_base + PMCTRL, val2);
	io_write32(pmc0_base + PMC_CTRL, val3);

	return 0;
}

int imx7ulp_cpu_suspend(uint32_t power_state __unused, uintptr_t entry,
			uint32_t context_id __unused, struct sm_nsec_ctx *nsec)
{
	uint32_t i;
	int ret;
	/*
	 * TODO: move the code to a platform init place, note that
	 * need to change kernel pm-imx6.c to avoid use LPRAM.
	 */
	uint32_t suspend_ocram_base = core_mmu_get_va(LP_OCRAM_START +
						      SUSPEND_OCRAM_OFFSET,
						      MEM_AREA_TEE_COHERENT);
	struct imx7ulp_pm_info *p =
			(struct imx7ulp_pm_info *)suspend_ocram_base;
	uint32_t type;

	type = (power_state & PSCI_POWER_STATE_TYPE_MASK) >>
		PSCI_POWER_STATE_TYPE_SHIFT;

	if (!suspended_init) {
		for (i = 0; i < ARRAY_SIZE(gpio_base); i++) {
			gpio_base[i] = core_mmu_get_va(GPIOC_BASE + i * 0x40,
						       MEM_AREA_IO_SEC);
		}
		scg1_base = core_mmu_get_va(SCG1_BASE, MEM_AREA_IO_SEC);
		pcc2_base = core_mmu_get_va(PCC2_BASE, MEM_AREA_IO_SEC);
		pcc3_base = core_mmu_get_va(PCC3_BASE, MEM_AREA_IO_SEC);
		iomuxc1_base = core_mmu_get_va(IOMUXC1_BASE, MEM_AREA_IO_SEC);
		tpm5_base = core_mmu_get_va(TPM5_BASE, MEM_AREA_IO_SEC);
		pmc0_base = core_mmu_get_va(PMC0_BASE, MEM_AREA_IO_SEC);
		pmc1_base = core_mmu_get_va(PMC1_BASE, MEM_AREA_IO_SEC);
		smc1_base = core_mmu_get_va(SMC1_BASE, MEM_AREA_IO_SEC);
		suspended_init = 1;
	}

	/* Store non-sec ctx regs */
	sm_save_unbanked_regs(&nsec->ub_regs);

	if (type == PSCI_POWER_STATE_TYPE_POWER_DOWN) {
		imx7ulp_gpio_save(p);
		imx7ulp_scg1_save(p);
		imx7ulp_pcc2_save(p);
		imx7ulp_pcc3_save(p);
		imx7ulp_tpm_save(p);
		imx7ulp_iomuxc_save(p);
		imx7ulp_set_lpm(VLLS);
		ret = sm_pm_cpu_suspend((uint32_t)p, (int (*)(uint32_t))
				(suspend_ocram_base + sizeof(*p)));
		imx7ulp_pcc2_restore(p);
		imx7ulp_pcc3_restore(p);
		imx7ulp_set_dgo(p, 0);
		imx7ulp_tpm_restore(p);
		imx7ulp_set_lpm(RUN);
	} else if (type == PSCI_POWER_STATE_TYPE_STANDBY) {
		imx7ulp_set_lpm(VLPS);
		io_write32(pmc1_base + PMC_VLPS,
			io_read32(pmc1_base + PMC_VLPS) | BM_VLPS_RBBEN);
		ret = sm_pm_cpu_suspend((uint32_t)p, (int (*)(uint32_t))
				(suspend_ocram_base + sizeof(*p)));
		io_write32(pmc1_base + PMC_VLPS,
			io_read32(pmc1_base + PMC_VLPS) & ~BM_VLPS_RBBEN);
		imx7ulp_set_lpm(RUN);
	}

	/*
	 * Sometimes cpu_suspend may not really suspended, we need to check
	 * it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	/* Restore register of different mode in secure world */
	sm_restore_unbanked_regs(&nsec->ub_regs);

	/* Back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

	DMSG("=== Back from Suspended ===\n");

	return 0;
}
