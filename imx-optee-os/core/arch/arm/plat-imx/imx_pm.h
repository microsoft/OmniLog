/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2019 NXP
 */

#ifndef __IMX_PM_H
#define __IMX_PM_H

#include <stdint.h>

#define MX6_MAX_MMDC_IO_NUM		36
#define MX6_MAX_MMDC_NUM		36

#define MX7_DDRC_NUM			32
#define MX7_DDRC_PHY_NUM		16

#define SUSPEND_OCRAM_SIZE			0xE00
#define LOWPOWER_IDLE_OCRAM_SIZE	0x1000

#define SUSPEND_OCRAM_OFFSET		0x0
#define LOWPOWER_IDLE_OCRAM_OFFSET	0xE00

#define BUSFREQ_OCRAM_OFFSET		(LOWPOWER_IDLE_OCRAM_OFFSET + \
					LOWPOWER_IDLE_OCRAM_SIZE)
#define BUSFREQ_MAX_SIZE		(IRAM_TBL_OFFSET - BUSFREQ_OCRAM_OFFSET)

#define PM_CORE_LEVEL			0
#define PM_CLUSTER_LEVEL		1
#define PM_SYSTEM_LEVEL			2

/*
 * Except i.MX6SX only 16KB ocram_s available, others use 16KB offset.
 */
#define IRAM_TBL_OFFSET			0x4000

#ifndef __ASSEMBLER__
#include <sm/sm.h>

/**
 * @brief   Definition of the struture given as first parameter to the
 *          sm_pm_cpu_suspend assembly function. This parameter is the
 *          argument of the device's power assembly function
 */
struct imx_pm_asm_arg {
	paddr_t pa_addr;  /// Physical address of the pm block
	void    *pm_info; /// Reference to the pm_info structure
};

extern int (*suspend_func)(uint32_t);
extern struct imx_pm_asm_arg suspend_arg;
extern vaddr_t pm_ocram_free_area;

/* This structure will be used for suspend/resume and low power idle */
struct imx6_pm_info {
	paddr_t		pa_base;	/* pa of pm_info */
	paddr_t		tee_resume;
	uint32_t	ddr_type;
	uint32_t	pm_info_size;
	paddr_t		mmdc0_pa_base;
	vaddr_t		mmdc0_va_base;
	paddr_t		mmdc1_pa_base;
	vaddr_t		mmdc1_va_base;
	paddr_t		src_pa_base;
	vaddr_t		src_va_base;
	paddr_t		iomuxc_pa_base;
	vaddr_t		iomuxc_va_base;
	paddr_t		ccm_pa_base;
	vaddr_t		ccm_va_base;
	paddr_t		gpc_pa_base;
	vaddr_t		gpc_va_base;
	vaddr_t		pl310_va_base;
	paddr_t		anatop_pa_base;
	vaddr_t		anatop_va_base;
/* i.mx6sx */
	paddr_t		sema4_pa_base;
	vaddr_t		sema4_va_base;
	uint32_t	ttbr0;
	uint32_t	ttbr1;
	uint32_t	diagnostic;
	uint32_t	idle_state;
	uint32_t	mmdc_io_num;
	uint32_t	mmdc_io_val[MX6_MAX_MMDC_IO_NUM][3];
	uint32_t	mmdc_num;
	uint32_t	mmdc_val[MX6_MAX_MMDC_NUM][2];
} __aligned(8);

struct imx6_pm_data {
	uint32_t   ddr_type;
	uint32_t   mmdc_io_num;
	const void *mmdc_io_offset;
	uint32_t   mmdc_num;
	const void *mmdc_offset;
};

/* The structure is used for suspend and low power idle */
struct imx7_pm_info {
	uint32_t	m4_reserve0;
	uint32_t	m4_reserve1;
	uint32_t	m4_reserve2;
	vaddr_t		va_base;	/* va of pm_info */
	paddr_t		pa_base;	/* pa of pm_info */
	uintptr_t	entry;
	paddr_t		tee_resume;
	uint32_t	ddr_type;
	uint32_t	pm_info_size;
	paddr_t		ddrc_pa_base;
	vaddr_t		ddrc_va_base;
	paddr_t		ddrc_phy_pa_base;
	vaddr_t		ddrc_phy_va_base;
	paddr_t		src_pa_base;
	vaddr_t		src_va_base;
	paddr_t		iomuxc_gpr_pa_base;
	vaddr_t		iomuxc_gpr_va_base;
	paddr_t		ccm_pa_base;
	vaddr_t		ccm_va_base;
	paddr_t		gpc_pa_base;
	vaddr_t		gpc_va_base;
	paddr_t		snvs_pa_base;
	vaddr_t		snvs_va_base;
	paddr_t		anatop_pa_base;
	vaddr_t		anatop_va_base;
	paddr_t		lpsr_pa_base;
	vaddr_t		lpsr_va_base;
	paddr_t		gic_pa_base;
	vaddr_t		gic_va_base;
	uint32_t	ttbr0;
	uint32_t	ttbr1;
	uint32_t	num_online_cpus;
	uint32_t	num_lpi_cpus;
	uint32_t	val;
	uint32_t	flag0;
	uint32_t	flag1;
	uint32_t	ddrc_num;
	uint32_t	ddrc_val[MX7_DDRC_NUM][2];
	uint32_t	ddrc_phy_num;
	uint32_t	ddrc_phy_val[MX7_DDRC_NUM][2];
} __aligned(8);

#define MX7ULP_MAX_IOMUX_NUM		116
#define MX7ULP_MAX_SELECT_INPUT_NUM	78
#define MX7ULP_MAX_MMDC_IO_NUM		36
#define MX7ULP_MAX_MMDC_NUM		50
struct imx7ulp_pm_info {
	uint32_t m4_reserve0;
	uint32_t m4_reserve1;
	uint32_t m4_reserve2;
	paddr_t pbase; /* The physical address of pm_info. */
	paddr_t resume_addr; /* The physical resume address for asm code */
	uint32_t pm_info_size; /* Size of pm_info. */
	vaddr_t sim_base;
	vaddr_t scg1_base;
	vaddr_t mmdc_base;
	vaddr_t mmdc_io_base;
	vaddr_t smc1_base;
	uint32_t scg1[17];
	uint32_t ttbr0;
	uint32_t ttbr1;
	uint32_t gpio[4][2];
	uint32_t iomux_num;
	uint32_t iomux_val[MX7ULP_MAX_IOMUX_NUM];
	uint32_t select_input_num;
	uint32_t select_input_val[MX7ULP_MAX_SELECT_INPUT_NUM];
	uint32_t mmdc_io_num;
	uint32_t mmdc_io_val[MX7ULP_MAX_MMDC_IO_NUM][2];
	uint32_t mmdc_num;
	uint32_t mmdc_val[MX7ULP_MAX_MMDC_NUM][2];
} __aligned(8);


struct imx7ulp_pm_data {
	uint32_t ddr_type;
	uint32_t mmdc_io_num;
	uint32_t *mmdc_io_offset;
	uint32_t mmdc_num;
	uint32_t *mmdc_offset;
};

struct imx7_pm_data {
	uint32_t ddr_type;
	uint32_t ddrc_num;
	uint32_t (*ddrc_offset)[2];
	uint32_t ddrc_phy_num;
	uint32_t (*ddrc_phy_offset)[2];
};

extern struct imx6_pm_data imx6ul_pm_data;
extern struct imx6_pm_data imx6sl_pm_data;
extern struct imx6_pm_data imx6sll_pm_data;
extern struct imx6_pm_data imx6sx_pm_data;

/* IMX6 Power initialization functions */
int imx6_suspend_init(void);
int imx6sx_cpuidle_init(void);
int imx6ul_cpuidle_init(void);
int imx6sl_cpuidle_init(void);
int imx6sll_cpuidle_init(void);

/* Low Power assembly functions */
void imx6_suspend(struct imx6_pm_info *info);
void imx6ul_low_power_idle(struct imx6_pm_info *info);
void imx6ull_low_power_idle(struct imx6_pm_info *info);
void imx6sx_low_power_idle(struct imx6_pm_info *info);
void imx6sl_low_power_idle(struct imx6_pm_info *info);
void imx6sll_low_power_idle(struct imx6_pm_info *info);
void imx6_resume(void);
void v7_cpu_resume(void);

uint32_t get_imx6sx_low_power_idle_size(void);
uint32_t get_imx6_suspend_size(void);


int imx6ul_lowpower_idle(uint32_t power_state, uintptr_t entry,
			 uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6sx_lowpower_idle(uint32_t power_state, uintptr_t entry,
			 uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6sll_lowpower_idle(uint32_t power_state, uintptr_t entry,
			  uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6sl_lowpower_idle(uint32_t power_state, uintptr_t entry,
			 uint32_t context_id, struct sm_nsec_ctx *nsec);
int imx6_cpu_suspend(uint32_t power_state, uintptr_t entry, uint32_t context_id,
		     struct sm_nsec_ctx *nsec);

/* IMX7 Power Initialization functions */
int imx7_suspend_init(void);
int imx7ulp_suspend_init(void);
int imx7d_cpuidle_init(void);

void imx7_suspend(struct imx7_pm_info *info);
void imx7_resume(void);
void ca7_cpu_resume(void);

int imx7_cpu_suspend(uint32_t power_state, uintptr_t entry, uint32_t context_id,
		     struct sm_nsec_ctx *nsec);
int imx7d_lowpower_idle(uint32_t power_state, uintptr_t entry,
			uint32_t context_id, struct sm_nsec_ctx *nsec);
void imx7d_low_power_idle(struct imx7_pm_info *info);

int imx7ulp_cpu_suspend(uint32_t power_state, uintptr_t entry,
			uint32_t context_id, struct sm_nsec_ctx *nsec);
void imx7ulp_suspend(struct imx7ulp_pm_info *info);
void imx7ulp_cpu_resume(void);

enum imx7ulp_sys_pwr_mode {
	HSRUN,
	RUN,
	VLPR,
	WAIT,
	VLPW,
	STOP,
	VLPS,
	VLLS,
};

/* IMX8 pm handlers */
unsigned long cpu_resume_handler(unsigned long a0, unsigned long a1);
unsigned long cpu_suspend_handler(unsigned long a0, unsigned long a1);

#endif
#endif
