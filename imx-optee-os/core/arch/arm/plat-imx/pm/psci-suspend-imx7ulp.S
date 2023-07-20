/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <kernel/unwind.h>
#include <asm.S>
#include <arm.h>
#include <arm32_macros.S>
#include <generated/imx_pm_asm_defines.h>
#include <platform_config.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/tz_proc_def.h>
#include <kernel/cache_helpers.h>

#define DGO_CTRL0	0x50
#define DGO_GPR3	0x60
#define DGO_GPR4	0x64

#define MX7ULP_MMDC_MISC	0x18
#define MX7ULP_MMDC_MAPSR	0x404
#define MX7ULP_MMDC_MPDGCTRL0	0x83c

#define SCG_RCCR	0x14
#define SCG_DDRCCR	0x30
#define SCG_NICCCR	0x40
#define SCG_FIRCDIV	0x304
#define SCG_APLLCSR	0x500
#define SCG_APLLDIV	0x504
#define SCG_APLLCFG	0x508
#define SCG_APLLPFD	0x50c
#define SCG_APLLNUM	0x510
#define SCG_APLLDENOM	0x514
#define SCG_SPLLCSR	0x600
#define SCG_SPLLDIV	0x604
#define SCG_SPLLCFG	0x608
#define SCG_SPLLPFD	0x60c
#define SCG_SPLLNUM	0x610
#define SCG_SPLLDENOM	0x614
#define SCG_SOSCDIV	0x104

#define PMC1_CTRL	0x24

#define GPIO_PDOR		0x0
#define GPIO_PDDR		0x14
#define GPIO_PORT_NUM		0x4
#define GPIO_PORT_OFF	0x40

#define PMCTRL		0x10

#define IOMUX_OFF		0x0
#define SELECT_INPUT_OFF	0x200

	.align 3

	.macro store_ttbr1

	/* Store TTBR1 to pm_info->ttbr1 */
	read_ttbr1 r7
	str	r7, [r0, #PM_INFO_MX7ULP_TTBR1_V_OFF]

	/* Store TTBR0 to pm_info->ttbr0 */
	read_ttbr0 r7
	str	r7, [r0, #PM_INFO_MX7ULP_TTBR0_V_OFF]

	/* Disable Branch Prediction, Z bit in SCTLR. */
	read_sctlr r6
	bic	r6, r6, #0x800
	write_sctlr r6

	/* Flush the BTAC. */
	write_bpiallis

	ldr	r6, =iram_tlb_phys_addr
	ldr	r6, [r6]
	dsb
	isb

	/* Store the IRAM table in TTBR */
	write_ttbr1 r6
	write_ttbr0 r6
	/* Read TTBCR and set PD0=1, N = 1 */
	read_ttbcr r6
	orr	r6, r6, #0x10
	write_ttbcr r6

	dsb
	isb

	/* flush the TLB */
	write_tlbiallis
	isb
	write_tlbiall
	isb

	.endm

	.macro restore_ttbr1

	/* Enable L1 data cache. */
	read_sctlr r6
	orr	r6, r6, #0x4
	write_sctlr r6

	dsb
	isb

	/* Restore TTBCR */
	/* Read TTBCR and set PD0=0, N = 0 */
	read_ttbcr r6
	bic	r6, r6, #0x10
	write_ttbcr r6
	dsb
	isb

	/* flush the TLB */
	write_tlbiallis

	/* Enable Branch Prediction, Z bit in SCTLR. */
	read_sctlr r6
	orr	r6, r6, #0x800
	write_sctlr r6

	/* Flush the Branch Target Address Cache (BTAC) */
	write_bpiallis

	/* Restore TTBR1, get the origin ttbr1 from pm info */
	ldr	r7, [r0, #PM_INFO_MX7ULP_TTBR1_V_OFF]
	write_ttbr1 r7
	ldr	r7, [r0, #PM_INFO_MX7ULP_TTBR0_V_OFF]
	write_ttbr0 r7

	.endm

	.macro	disable_l1_dcache

	/*
	 * Flush all data from the L1 data cache before disabling
	 * SCTLR.C bit.
	 */
	push	{r0 - r10, lr}
	ldr	r1, =dcache_op_all
	mov	r0, #DCACHE_OP_CLEAN_INV
	mov	lr, pc
	bx	r1
	pop	{r0 - r10, lr}

	/* disable d-cache */
	mrc	p15, 0, r7, c1, c0, 0
	bic	r7, r7, #(1 << 2)
	mcr	p15, 0, r7, c1, c0, 0
	dsb
	isb

	push	{r0 - r10, lr}
	ldr	r1, =dcache_op_all
	mov	r0, #DCACHE_OP_CLEAN_INV
	mov	lr, pc
	bx	r1
	pop	{r0 - r10, lr}


	.endm

	.macro	restore_mmdc_settings

	ldr	r10, =MMDC_IO_BASE
	ldr	r11, =MMDC_BASE

	/* resume mmdc iomuxc settings */
	ldr	r6, [r0, #PM_INFO_MX7ULP_MMDC_IO_NUM_OFF]
	ldr	r7, =PM_INFO_MX7ULP_MMDC_IO_VAL_OFF
	add	r7, r7, r0
11:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	str	r9, [r10, r8]
	subs	r6, r6, #0x1
	bne	11b

	/* restore MMDC settings */
	ldr	r6, [r0, #PM_INFO_MX7ULP_MMDC_NUM_OFF]
	ldr	r7, =PM_INFO_MX7ULP_MMDC_VAL_OFF
	add	r7, r7, r0
1:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	str	r9, [r11, r8]
	subs	r6, r6, #0x1
	bne	1b

	/* let DDR enter self-refresh */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	orr	r7, r7, #(1 << 20)
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]
2:
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	beq	2b

	/* let DDR out of self-refresh */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	bic	r7, r7, #(1 << 20)
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]
3:
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	bne	3b

	/* kick off MMDC */
	ldr	r4, =0x0
	str	r4, [r11, #0x1c]

	/* let DDR out of self-refresh */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	bic	r7, r7, #(1 << 20)
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]
4:
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	bne	4b

	/* enable DDR auto power saving */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	bic	r7, r7, #0x1
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]

	.endm

FUNC imx7ulp_suspend, :
UNWIND( .fnstart)
	push	{r4-r12}

	/*
	 * The value of r0 is mapped the same in origin table and IRAM table,
	 * thus no need to care r0 here.
	 */
	ldr	r1, [r0, #PM_INFO_MX7ULP_PBASE_OFF]
	ldr	r2, [r0, #PM_INFO_MX7ULP_RESUME_ADDR_OFF]
	ldr	r3, [r0, #PM_INFO_MX7ULP_SIZE_OFF]

	/*
	 * counting the resume address in iram
	 * to set it in SRC register.
	 */
	ldr	r6, =imx7ulp_suspend
	ldr	r7, =resume
	sub	r7, r7, r6
	add	r8, r1, r3
	add	r9, r8, r7

	ldr	r11, [r0, #PM_INFO_MX7ULP_SIM_VBASE_OFF]
	/* store physical resume addr and pm_info address. */
	str	r9, [r11, #DGO_GPR3]
	str	r1, [r11, #DGO_GPR4]
	ldr	r7, [r11, #DGO_CTRL0]
	orr	r7, r7, #0xc
	str	r7, [r11, #DGO_CTRL0]
wait_dgo:
	ldr	r7, [r11, #DGO_CTRL0]
	and	r7, r7, #0x18000
	cmp	r7, #0x18000
	bne	wait_dgo

	ldr	r7, [r11, #DGO_CTRL0]
	orr	r7, r7, #0x18000
	bic	r7, r7, #0xc
	str	r7, [r11, #DGO_CTRL0]

	disable_l1_dcache

	store_ttbr1

	ldr	r11, [r0, #PM_INFO_MX7ULP_MMDC_VBASE_OFF]

	/*
	 * put DDR explicitly into self-refresh and
	 * disable automatic power savings.
	 */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	orr	r7, r7, #0x1
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]

	/* make the DDR explicitly enter self-refresh. */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	orr	r7, r7, #(1 << 20)
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]

poll_dvfs_set:
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	beq	poll_dvfs_set

	/* switch NIC clock to FIRC */
	ldr	r10, [r0, #PM_INFO_MX7ULP_SCG1_VBASE_OFF]
	ldr	r7, [r10, #SCG_NICCCR]
	bic	r7, #(1 << 28)
	str	r7, [r10, #SCG_NICCCR]

	/* switch RUN clock to FIRC */
	ldr	r7, [r10, #SCG_RCCR]
	bic	r7, #(0xf << 24)
	orr	r7, #(0x3 << 24)
	str	r7, [r10, #SCG_RCCR]

	/* turn off SPLL and SPFD */
	ldr	r7, [r10, #SCG_SPLLPFD]
	mov	r8, r7
	orr	r7, r7, #(0x1 << 31)
	orr	r7, r7, #(0x1 << 23)
	orr	r7, r7, #(0x1 << 15)
	orr	r7, r7, #(0x1 << 7)
	str	r7, [r10, #SCG_SPLLPFD]

	ldr	r7, [r10, #SCG_SPLLCSR]
	bic	r7, r7, #0x1
	str	r7, [r10, #SCG_SPLLCSR]

	/* turn off APLL and APFD */
	ldr	r7, [r10, #SCG_APLLPFD]
	mov	r9, r7
	orr	r7, r7, #(0x1 << 31)
	orr	r7, r7, #(0x1 << 23)
	orr	r7, r7, #(0x1 << 15)
	orr	r7, r7, #(0x1 << 7)
	str	r7, [r10, #SCG_APLLPFD]

	ldr	r7, [r10, #SCG_APLLCSR]
	bic	r7, r7, #0x1
	str	r7, [r10, #SCG_APLLCSR]

	/* Zzz, enter stop mode */
	wfi
	nop
	nop
	nop
	nop

	/* clear core0's entry and parameter */
	ldr	r10, [r0, #PM_INFO_MX7ULP_SIM_VBASE_OFF]
	mov	r7, #0x0
	str	r7, [r10, #DGO_GPR3]
	str	r7, [r10, #DGO_GPR4]

	/* enable SPLL and SPFD */
	ldr	r10, [r0, #PM_INFO_MX7ULP_SCG1_VBASE_OFF]
	ldr	r7, [r10, #SCG_SPLLCSR]
	orr	r7, r7, #1
	str	r7, [r10, #SCG_SPLLCSR]
wait_spll:
	ldr	r7, [r10, #SCG_SPLLCSR]
	ands	r7, r7, #(1 << 24)
	beq	wait_spll

	str	r8, [r10, #SCG_SPLLPFD]
	/* switch RUN clock to SPLL */
	ldr	r7, [r10, #SCG_RCCR]
	bic	r7, #(0xf << 24)
	orr	r7, #(0x6 << 24)
	str	r7, [r10, #SCG_RCCR]

	/* enable APLL and APFD */
	ldr	r7, [r10, #SCG_APLLCSR]
	orr	r7, r7, #1
	str	r7, [r10, #SCG_APLLCSR]
wait_apll:
	ldr	r7, [r10, #SCG_APLLCSR]
	ands	r7, r7, #(1 << 24)
	beq	wait_apll

	str	r9, [r10, #SCG_APLLPFD]

	/* switch NIC clock to DDR */
	ldr	r7, [r10, #SCG_NICCCR]
	orr	r7, #(1 << 28)
	str	r7, [r10, #SCG_NICCCR]

	/* let DDR out of self-refresh */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	bic	r7, r7, #(1 << 20)
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]
poll_dvfs_clear:
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	bne	poll_dvfs_clear

	/* enable DDR auto power saving */
	ldr	r7, [r11, #MX7ULP_MMDC_MAPSR]
	bic	r7, r7, #0x1
	str	r7, [r11, #MX7ULP_MMDC_MAPSR]

	restore_ttbr1
	pop	{r4-r12}
	/* return to suspend finish */
	bx	lr

resume:
	/* invalidate L1 I-cache first */
	mov     r6, #0x0
	mcr     p15, 0, r6, c7, c5, 0
	mcr     p15, 0, r6, c7, c5, 6
	/* enable the Icache and branch prediction */
	mov     r6, #0x1800
	mcr     p15, 0, r6, c1, c0, 0
	isb

	/* monitor mode */
	mov	r3, #0x16
	mov	r4, #((1 << 6) | (1 << 7))
	orr	r3, r3, r4
	msr	cpsr, r3
	nop
	nop
	nop

	ldr	r6, =SIM_BASE
	ldr	r0, [r6, #DGO_GPR4]
	/* get physical resume address from pm_info. */
	ldr	lr, [r0, #PM_INFO_MX7ULP_RESUME_ADDR_OFF]

	ldr	r11, =SCG1_BASE
	/* enable spll and pfd0 */
	ldr	r5, =PM_INFO_MX7ULP_SCG1_VAL_OFF
	add	r6, r5, #48
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SPLLCFG]

	add	r6, r5, #56
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SPLLNUM]

	add	r6, r5, #60
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SPLLDENOM]

	add	r6, r5, #40
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SPLLCSR]
5:
	ldr	r7, [r11, #SCG_SPLLCSR]
	ands	r7, r7, #0x1000000
	beq	5b

	add	r6, r5, #44
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SPLLDIV]

	add	r6, r5, #52
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SPLLPFD]

	add	r6, r5, #0
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_RCCR]

	/* enable apll and pfd0 */
	add	r6, r5, #24
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_APLLCFG]

	add	r6, r5, #32
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_APLLNUM]

	add	r6, r5, #36
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_APLLDENOM]

	add	r6, r5, #16
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_APLLCSR]
6:
	ldr	r7, [r11, #SCG_APLLCSR]
	ands	r7, r7, #0x1000000
	beq	6b

	add	r6, r5, #20
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_APLLDIV]

	add	r6, r5, #28
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_APLLPFD]

	/* set ddr ccr */
	add	r6, r5, #4
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_DDRCCR]

	/* set nic sel */
	add	r6, r5, #8
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_NICCCR]

	/* set firc div2 to get 48MHz */
	add	r6, r5, #12
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_FIRCDIV]

	/* restore system OSC div */
	add	r6, r5, #64
	ldr	r7, [r0, r6]
	str	r7, [r11, #SCG_SOSCDIV]

	/* enable mmdc clock in pcc3 */
	ldr	r11, =PCC3_BASE
	ldr	r7, [r11, #0xac]
	orr	r7, r7, #(1 << 30)
	str	r7, [r11, #0xac]

	/* enable GPIO clock in pcc2 */
	ldr	r11, =PCC2_BASE
	ldr	r7, [r11, #0x3c]
	orr	r7, r7, #(1 << 30)
	str	r7, [r11, #0x3c]

	/* restore gpio settings */
	ldr	r10, =GPIOC_BASE
	ldr	r7, =PM_INFO_MX7ULP_GPIO_REG_OFF
	add	r7, r7, r0
	ldr	r6, =GPIO_PORT_NUM
12:
	ldr	r9, [r7], #0x4
	str	r9, [r10, #GPIO_PDOR]
	ldr	r9, [r7], #0x4
	str	r9, [r10, #GPIO_PDDR]
	add     r10, r10, #GPIO_PORT_OFF
	subs	r6, r6, #0x1
	bne	12b

	/* restore iomuxc settings */
	ldr	r10, =IOMUXC1_BASE
	add	r10, r10, #IOMUX_OFF
	ldr	r6, [r0, #PM_INFO_MX7ULP_IOMUX_NUM_OFF]
	ldr	r7, =PM_INFO_MX7ULP_IOMUX_VAL_OFF
	add	r7, r7, r0
13:
	ldr	r9, [r7], #0x4
	str	r9, [r10], #0x4
	subs	r6, r6, #0x1
	bne	13b

	/* restore select input settings */
	ldr	r10, =IOMUXC1_BASE
	add	r10, r10, #SELECT_INPUT_OFF
	ldr	r6, [r0, #PM_INFO_MX7ULP_SELECT_INPUT_NUM_OFF]
	ldr	r7, =PM_INFO_MX7ULP_SELECT_INPUT_VAL_OFF
	add	r7, r7, r0
14:
	ldr	r9, [r7], #0x4
	str	r9, [r10], #0x4
	subs	r6, r6, #0x1
	bne	14b

	/* isoack */
	ldr	r6, =PMC1_BASE
	ldr	r7, [r6, #PMC1_CTRL]
	orr	r7, r7, #(1 << 14)
	str	r7, [r6, #PMC1_CTRL]

	restore_mmdc_settings

	mov	pc, lr
UNWIND( .fnend)
END_FUNC imx7ulp_suspend

FUNC imx7ulp_cpu_resume, :
UNWIND( .fnstart)
	mov	r0, #0
	mcr     p15, 2, r0, c0, c0, 0
	isb

_inv_dcache_off:
	mov	r0, #0
_inv_nextWay:
	mov	r1, #0
_inv_nextLine:
	orr     r2, r0, r1
	mcr     p15, 0, r2, c7, c6, 2
	add     r1, r1, #1 << LINE_FIELD_OFFSET
	cmp     r1, #1 << LINE_FIELD_OVERFLOW
	bne	_inv_nextLine
	add	r0, r0, #1 << WAY_FIELD_OFFSET
	cmp	r0, #0
	bne	_inv_nextWay

	dsb
	nop
	nop

	/*
	 * No stack, scratch r0-r3
	 * TODO: Need to use specific configure, but not plat_xxx.
	 * Because plat_xx maybe changed in future, we can not rely on it.
	 * Need handle sp carefully.
	 */
	blx	plat_cpu_reset_early

	b	sm_pm_cpu_resume
UNWIND( .fnend)
END_FUNC imx7ulp_cpu_resume
