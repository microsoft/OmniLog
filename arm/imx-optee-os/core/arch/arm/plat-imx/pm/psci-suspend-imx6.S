/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2017-2018, 2020 NXP
 *
 */

#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <generated/imx_pm_asm_defines.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_proc_def.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/unwind.h>
#include <platform_config.h>

	.section .text.psci.suspend

	/* Check if the cpu is cortex-a7 */
	.macro is_cortex_a7

	/* Read the primary cpu number is MPIDR */
	mrc     p15, 0, r5, c0, c0, 0
	ldr     r6, =0xfff0
	and     r5, r5, r6
	ldr     r6, =0xc070
	cmp     r5, r6

	.endm

#define L2X0_CACHE_SYNC                 0x730
#define PL310_8WAYS_MASK		0x00FF
#define PL310_16WAYS_UPPERMASK		0xFF00
#define PL310_LOCKDOWN_SZREG		4
#define PL310_LOCKDOWN_NBREGS		8

	.macro  sync_l2_cache pl310_base

	/* sync L2 cache to drain L2's buffers to DRAM. */
#ifdef CFG_PL310
	mov	r6, #0x0
	str	r6, [\pl310_base, #L2X0_CACHE_SYNC]
1:
	ldr	r6, [\pl310_base, #L2X0_CACHE_SYNC]
	ands	r6, r6, #0x1
	bne	1b
#endif

	.endm

	/* r11 must be MMDC0 base address */
	/* r12 must be MMDC1 base address */
	.macro reset_read_fifo

	/* reset read FIFO, RST_RD_FIFO */
	ldr	r7, =MX6Q_MMDC_MPDGCTRL0
	ldr	r6, [r11, r7]
	orr     r6, r6, #(1 << 31)
	str	r6, [r11, r7]
2:
	ldr	r6, [r11, r7]
	ands	r6, r6, #(1 << 31)
	bne	2b

	/* reset FIFO a second time */
	ldr	r6, [r11, r7]
	orr     r6, r6, #(1 << 31)
	str	r6, [r11, r7]
3:
	ldr	r6, [r11, r7]
	ands	r6, r6, #(1 << 31)
	bne	3b

	/* check if second channel mode is enabled */
	ldr	r7, =MX6Q_MMDC_MISC
	ldr	r6, [r11, r7]
	ands	r6, r6, #(1 << 2)
	beq	6f

	ldr	r7, =MX6Q_MMDC_MPDGCTRL0
	ldr	r6, [r12, r7]
	orr     r6, r6, #(1 << 31)
	str	r6, [r12, r7]
4:
	ldr	r6, [r12, r7]
	ands	r6, r6, #(1 << 31)
	bne	4b

	ldr	r6, [r12, r7]
	orr     r6, r6, #(1 << 31)
	str	r6, [r12, r7]
5:
	ldr	r6, [r12, r7]
	ands	r6, r6, #(1 << 31)
	bne	5b

6:
	.endm

	/* r11 must be MMDC base address */
	/* r12 must be MMDC1 base address */
	.macro mmdc_out_and_auto_self_refresh

	/* let DDR out of self-refresh */
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #(1 << 21)
	str	r7, [r11, #MX6Q_MMDC_MAPSR]
7:
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	bne	7b

	/* enable DDR auto power saving */
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #0x1
	str	r7, [r11, #MX6Q_MMDC_MAPSR]

	/* check if lppdr2 2 channel mode is enabled */
	ldr	r7, =MX6Q_MMDC_MISC
	ldr	r6, [r11, r7]
	ands	r6, r6, #(1 << 2)
	beq	9f

	ldr	r7, [r12, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #(1 << 21)
	str	r7, [r12, #MX6Q_MMDC_MAPSR]
8:
	ldr	r7, [r12, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	bne	8b

	ldr	r7, [r12, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #0x1
	str	r7, [r12, #MX6Q_MMDC_MAPSR]
9:
	.endm

	/* r10 must be iomuxc base address */
	.macro resume_iomuxc_gpr

	add	r10, r10, #0x4000
	/* IOMUXC GPR DRAM_RESET_BYPASS */
	ldr	r4, [r10, #0x8]
	bic	r4, r4, #(0x1 << 27)
	str	r4, [r10, #0x8]
	/* IOMUXC GPR DRAM_CKE_BYPASS */
	ldr	r4, [r10, #0x8]
	bic	r4, r4, #(0x1 << 31)
	str	r4, [r10, #0x8]

	.endm

	.macro	resume_io

	/* restore MMDC IO */
	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_IOMUXC_V_OFF]
	ldrne	r10, [r0, #PM_INFO_IOMUXC_P_OFF]

	ldr	r6, [r0, #PM_INFO_MMDC_IO_NUM_OFF]
	ldr	r7, =PM_INFO_MMDC_IO_VAL_OFF
	add	r7, r7, r0
10:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x8
	str	r9, [r10, r8]
	subs	r6, r6, #0x1
	bne	10b

	cmp	r5, #0x0
	/* Here only MMDC0 is set */
	ldreq	r11, [r0, #PM_INFO_MMDC0_V_OFF]
	ldrne	r11, [r0, #PM_INFO_MMDC0_P_OFF]
	ldreq	r12, [r0, #PM_INFO_MMDC1_V_OFF]
	ldrne	r12, [r0, #PM_INFO_MMDC1_P_OFF]

	reset_read_fifo
	mmdc_out_and_auto_self_refresh

	.endm

	.macro	resume_mmdc_io

	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_IOMUXC_V_OFF]
	ldrne	r10, [r0, #PM_INFO_IOMUXC_P_OFF]
	ldreq	r11, [r0, #PM_INFO_MMDC0_V_OFF]
	ldrne	r11, [r0, #PM_INFO_MMDC0_P_OFF]
	ldreq	r12, [r0, #PM_INFO_MMDC1_V_OFF]
	ldrne	r12, [r0, #PM_INFO_MMDC1_P_OFF]

	/* resume mmdc iomuxc settings */
	ldr	r6, [r0, #PM_INFO_MMDC_IO_NUM_OFF]
	ldr	r7, =PM_INFO_MMDC_IO_VAL_OFF
	add	r7, r7, r0
11:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x8
	str	r9, [r10, r8]
	subs	r6, r6, #0x1
	bne	11b

	/* check whether we need to restore MMDC */
	cmp	r5, #0x0
	beq	12f

	/* check whether last suspend is with M/F mix off */
	ldr	r9, [r0, #PM_INFO_GPC_P_OFF]
	ldr	r6, [r9, #0x220]
	cmp	r6, #0x0
	bne	13f
12:
	resume_iomuxc_gpr
	reset_read_fifo

	b	17f
13:
	/*
	 * This part of code is executed only if
	 * MMU is OFF
     */

	/* restore MMDC settings */
	ldr	r6, [r0, #PM_INFO_MMDC_NUM_OFF]
	ldr	r7, =PM_INFO_MMDC_VAL_OFF
	add	r7, r7, r0
14:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	str	r9, [r11, r8]
	subs	r6, r6, #0x1
	bne	14b

	/* let DDR enter self-refresh */
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #(1 << 20)
	str	r7, [r11, #MX6Q_MMDC_MAPSR]
15:
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	beq	15b

	resume_iomuxc_gpr
	reset_read_fifo

	/* let DDR out of self-refresh */
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #(1 << 20)
	str	r7, [r11, #MX6Q_MMDC_MAPSR]
16:
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 24)
	bne	16b

	/* kick off MMDC */
	ldr	r4, =0x0
	str	r4, [r11, #0x1c]

17:
	mmdc_out_and_auto_self_refresh

	.endm

	.macro store_ttbr1

	/* Store TTBR1 to pm_info->ttbr1 */
	read_ttbr1	r7
	str		r7, [r0, #PM_INFO_TTBR1_OFF]

	/* Disable Branch Prediction, Z bit in SCTLR. */
	read_sctlr	r6
	bic		r6, r6, #SCTLR_Z
	write_sctlr	r6

	/* Flush the BTAC. */
	write_bpiallis

	/* Store the IRAM table in TTBR1 */
	ldr	r6, =iram_tlb_phys_addr
	ldr	r6, [r6]
	dsb
	isb
	write_ttbr1 r6

	/* Read TTBCR and set PD0=1 and PD1=0 */
	/* Warning: unknown behaviour if LPAE is enabled */
#ifdef CFG_WITH_LPAE
#error "Case not supported"
#endif
	read_ttbcr	r6
	bic		r6, r6, #0x30
	orr		r6, r6, #0x10
	write_ttbcr	r6
	dsb
	isb

	/* flush the TLB */
	write_tlbiallis
	isb
	write_tlbiall
	isb

17:
	.endm

	.macro restore_ttbr1

	/* Enable L1 data cache. */
	read_sctlr	r6
	orr		r6, r6, #SCTLR_C
	write_sctlr	r6
	dsb
	isb

	/* Restore TTBCR */
	/* Read TTBCR and set PD0=0 and PD1=0 */
	read_ttbcr	r6
	bic		r6, r6, #0x30
	write_ttbcr	r6
	dsb
	isb

	/* flush the TLB */
	write_tlbiallis

	/* Enable Branch Prediction */
	read_sctlr	r6
	orr		r6, r6, #SCTLR_Z
	write_sctlr	r6

	/* Flush the Branch Target Address Cache (BTAC) */
	write_bpiallis

	/* Restore TTBR1, get the origin ttbr1 from pm info */
	ldr		r6, [r0, #PM_INFO_TTBR1_OFF]
	write_ttbr1	r6
	isb

#ifdef CFG_PL310
	/* Unlock L2 */
	ldr		r5, [r0, #PM_INFO_PL310_V_OFF]
	unlock_l2	r5
#endif
	.endm

	/* Expect PL310 base address */
	/* Uses r6, r7, r11 */
	.macro lock_l2 base

	ldr	r6, [\base, #PL310_AUX_CTRL]
	tst	r6, #PL310_AUX_16WAY_BIT
	mov	r6, #PL310_8WAYS_MASK
	orrne	r6, #PL310_16WAYS_UPPERMASK
	mov	r7, #PL310_LOCKDOWN_NBREGS
	add	r11, \base, #PL310_DCACHE_LOCKDOWN_BASE
19:	/* lock Dcache and Icache */
	str	r6, [r11], #PL310_LOCKDOWN_SZREG
	str	r6, [r11], #PL310_LOCKDOWN_SZREG
	subs	r7, r7, #1
	bne	19b

	.endm

	/* Expect PL310 base address */
	/* Uses r6, r7, r11 */
	.macro unlock_l2 base

	ldr	r6, [\base, #PL310_AUX_CTRL]
	tst	r6, #PL310_AUX_16WAY_BIT
	mov	r6, #0x00
	orrne	r6, #0x0000
	mov	r7, #PL310_LOCKDOWN_NBREGS
	add	r11, \base, #PL310_DCACHE_LOCKDOWN_BASE
20:	/* unlock Dcache and Icache */
	str	r6, [r11], #PL310_LOCKDOWN_SZREG
	str	r6, [r11], #PL310_LOCKDOWN_SZREG
	subs	r7, r7, #1
	bne	20b

	.endm

	.align 3
/**
 * @brief   Prepare and switch the device to enter in suspend mode.
 *          Function is executed in OCRAM.
 *          If success, the device is reset.
 *          Operation can be cancel and in this case the device is
 *          not reset, and returns to the caller.
 *
 *          Input parameter is a reference to a imx_pm_asm_arg structure
 *          containing the function argument (refer to the imx_pm.h)
 *
 * @param[in] r0  reference to the structure imx_pm_asm_arg in normal
 *                memory.
 */
FUNC imx6_suspend, :
UNWIND( .fnstart)
	/* Get the function arguments data */
	ldr	r1, [r0, #PM_ASM_ARG_PA_ADDR_OFF]
	ldr	r0, [r0, #PM_ASM_ARG_PM_INFO_OFF]

	/*
	 * Calculate the Physical address of the resume function
	 * to initialize the SRC register
	 */
	ldr	r6, =imx6_suspend
	ldr	r9, =resume
	sub	r9, r6
	add	r9, r1

	ldr	r1, [r0, #PM_INFO_PBASE_OFF]

	/*
	 * make sure TLB contain the addr we want,
	 * as we will access them after MMDC IO floated.

	 * TODO: Can we drop this?
	 * If we disable MMU in secureity, may need to change to P_OFFSET
	 */

	ldr	r11, [r0, #PM_INFO_CCM_V_OFF]
	ldr	r6, [r11, #0x0]
	ldr	r11, [r0, #PM_INFO_GPC_V_OFF]
	ldr	r6, [r11, #0x0]
	ldr	r11, [r0, #PM_INFO_IOMUXC_V_OFF]
	ldr	r6, [r11, #0x0]

	/* use r11 to store the IO address */
	ldr	r11, [r0, #PM_INFO_SRC_V_OFF]
	/*
	 * store physical resume addr and pm_info address.
	 * SRC_GPR2 will be passed as arg to resume func.
	 */
	str	r9, [r11, #SRC_GPR1]
	str	r1, [r11, #SRC_GPR2]

	push	{r0 - r10, lr}

#if CFG_PL310
	/* Save pm_info to r12 */
	mov	r12, r0

	/* Lock L2 */
	ldr		r0, [r12, #PM_INFO_PL310_V_OFF]
	lock_l2		r0

	/* Sync L2 */
	ldr		r11, [r12, #PM_INFO_PL310_V_OFF]
	sync_l2_cache	r11

	/* Clean L2 */
	ldr	r0, [r12, #PM_INFO_PL310_V_OFF]
	ldr	r1, =arm_cl2_cleaninvbyway
	mov	lr, pc
	bx	r1

	/* Sync L2 */
	ldr		r11, [r12, #PM_INFO_PL310_V_OFF]
	sync_l2_cache	r11
#endif
	/* Clean L1$ */
	ldr	r1, =dcache_op_all
	mov	r0, #DCACHE_OP_CLEAN_INV
	mov	lr, pc
	bx	r1

	/* Disable L1$ */
	read_sctlr	r0
	bic		r0, r0, #SCTLR_C
	write_sctlr	r0
	dsb
	isb

	/* Clean L1$ */
	ldr	r1, =dcache_op_all
	mov	r0, #DCACHE_OP_CLEAN_INV
	mov	lr, pc
	bx	r1

	pop	{r0 - r10, lr}

	store_ttbr1

	ldr	r11, [r0, #PM_INFO_MMDC0_V_OFF]
	ldr	r12, [r0, #PM_INFO_MMDC1_V_OFF]
	/*
	 * put DDR explicitly into self-refresh and
	 * disable automatic power savings.
	 */
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #0x1
	str	r7, [r11, #MX6Q_MMDC_MAPSR]

	/* make the DDR explicitly enter self-refresh. */
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #(1 << 21)
	str	r7, [r11, #MX6Q_MMDC_MAPSR]

poll_dvfs_set:
	ldr	r7, [r11, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	beq	poll_dvfs_set

	/* check if lppdr2 2 channel mode is enabled */
	ldr	r7, =MX6Q_MMDC_MISC
	ldr	r6, [r11, r7]
	ands	r6, r6, #(1 << 2)
	beq	skip_self_refresh_ch1

	ldr	r7, [r12, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #0x1
	str	r7, [r12, #MX6Q_MMDC_MAPSR]

	ldr	r7, [r12, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #(1 << 21)
	str	r7, [r12, #MX6Q_MMDC_MAPSR]

poll_dvfs_set_ch1:
	ldr	r7, [r12, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	beq	poll_dvfs_set_ch1

skip_self_refresh_ch1:
	/* use r11 to store the IO address */
	ldr	r11, [r0, #PM_INFO_IOMUXC_V_OFF]
	ldr	r6, [r0, #PM_INFO_MMDC_IO_NUM_OFF]
	ldr	r8, =PM_INFO_MMDC_IO_VAL_OFF
	add	r8, r8, r0
set_mmdc_io_lpm:
	ldr	r7, [r8], #0x8
	ldr	r9, [r8], #0x4
	str	r9, [r11, r7]
	subs	r6, r6, #0x1
	bne	set_mmdc_io_lpm

	/* check whether it supports Mega/Fast off */
	ldr	r6, [r0, #PM_INFO_MMDC_NUM_OFF]
	cmp	r6, #0x0
	beq	set_mmdc_lpm_done

	/* IOMUXC GPR DRAM_RESET */
	add	r11, r11, #0x4000
	ldr	r6, [r11, #0x8]
	orr	r6, r6, #(0x1 << 28)
	str	r6, [r11, #0x8]

	/* IOMUXC GPR DRAM_RESET_BYPASS */
	ldr	r6, [r11, #0x8]
	orr	r6, r6, #(0x1 << 27)
	str	r6, [r11, #0x8]

	/* IOMUXC GPR DRAM_CKE_BYPASS */
	ldr	r6, [r11, #0x8]
	orr	r6, r6, #(0x1 << 31)
	str	r6, [r11, #0x8]
set_mmdc_lpm_done:

	/*
	 * mask all GPC interrupts before
	 * enabling the RBC counters to
	 * avoid the counter starting too
	 * early if an interrupt is already
	 * pending.
	 */
	ldr	r11, [r0, #PM_INFO_GPC_V_OFF]
	ldr	r6, [r11, #MX6Q_GPC_IMR1]
	ldr	r7, [r11, #MX6Q_GPC_IMR2]
	ldr	r8, [r11, #MX6Q_GPC_IMR3]
	ldr	r9, [r11, #MX6Q_GPC_IMR4]

	ldr	r10, =0xffffffff
	str	r10, [r11, #MX6Q_GPC_IMR1]
	str	r10, [r11, #MX6Q_GPC_IMR2]
	str	r10, [r11, #MX6Q_GPC_IMR3]
	str	r10, [r11, #MX6Q_GPC_IMR4]

	/*
	 * enable the RBC bypass counter here
	 * to hold off the interrupts. RBC counter
	 * = 32 (1ms), Minimum RBC delay should be
	 * 400us for the analog LDOs to power down.
	 */
	ldr	r11, [r0, #PM_INFO_CCM_V_OFF]
	ldr	r10, [r11, #MX6Q_CCM_CCR]
	bic	r10, r10, #(0x3f << 21)
	orr	r10, r10, #(0x20 << 21)
	str	r10, [r11, #MX6Q_CCM_CCR]

	/* enable the counter. */
	ldr	r10, [r11, #MX6Q_CCM_CCR]
	orr	r10, r10, #(0x1 << 27)
	str	r10, [r11, #MX6Q_CCM_CCR]

	/* unmask all the GPC interrupts. */
	ldr	r11, [r0, #PM_INFO_GPC_V_OFF]
	str	r6, [r11, #MX6Q_GPC_IMR1]
	str	r7, [r11, #MX6Q_GPC_IMR2]
	str	r8, [r11, #MX6Q_GPC_IMR3]
	str	r9, [r11, #MX6Q_GPC_IMR4]

	/*
	 * now delay for a short while (3usec)
	 * ARM is at 1GHz at this point
	 * so a short loop should be enough.
	 * this delay is required to ensure that
	 * the RBC counter can start counting in
	 * case an interrupt is already pending
	 * or in case an interrupt arrives just
	 * as ARM is about to assert DSM_request.
	 */
	ldr	r6, =2000
rbc_loop:
	subs	r6, r6, #0x1
	bne	rbc_loop

	/*
	 * ERR005852 Analog: Transition from Deep Sleep Mode to
	 * LDO Bypass Mode may cause the slow response of the
	 * VDDARM_CAP output.
	 *
	 * Software workaround:
	 * if internal ldo(VDDARM) bypassed, switch to analog bypass
	 * mode (0x1E), prio to entering DSM, and then, revert to the
	 * normal bypass mode, when exiting from DSM.
	 */
	ldr	r11, [r0, #PM_INFO_ANATOP_V_OFF]
	ldr	r10, [r11, #MX6Q_ANATOP_CORE]
	and	r10, r10, #0x1f
	cmp	r10, #0x1f
	bne	ldo_check_done1
ldo_analog_bypass:
	ldr	r10, [r11, #MX6Q_ANATOP_CORE]
	bic	r10, r10, #0x1f
	orr	r10, r10, #0x1e
	str	r10, [r11, #MX6Q_ANATOP_CORE]
ldo_check_done1:

	dsb
	dmb
	isb

	/* enter stop mode */
	wfi
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	/*
	 * Run to here means there is pending GPC wakeup interrupt.
	 */
	/* restore it with 0x1f if use ldo bypass mode.*/
	ldr	r10, [r11, #MX6Q_ANATOP_CORE]
	and	r10, r10, #0x1f
	cmp	r10, #0x1e
	bne	ldo_check_done2
ldo_bypass_restore:
	ldr	r10, [r11, #MX6Q_ANATOP_CORE]
	orr	r10, r10, #0x1f
	str	r10, [r11, #MX6Q_ANATOP_CORE]
ldo_check_done2:
	mov	r5, #0x0

	/* check whether it supports Mega/Fast off */
	ldr	r6, [r0, #PM_INFO_MMDC_NUM_OFF]
	cmp	r6, #0x0
	beq	only_resume_io
	resume_mmdc_io
	b	resume_mmdc_done
only_resume_io:
	resume_io
resume_mmdc_done:
	/* Clear CORE0's entry and arg */
	ldr	r11, [r0, #PM_INFO_SRC_V_OFF]
	mov	r7, #0
	str	r7, [r11, #SRC_GPR1]
	str	r7, [r11, #SRC_GPR2]

	restore_ttbr1

	/* return to cpu_suspend */
	bx	lr

resume:
	/* monitor mode */
	mov	r3, #0x16
	mov	r4, #((1 << 6) | (1 << 7))
	orr	r3, r3, r4
	msr	cpsr, r3
	nop
	nop
	nop
	/*
	 * Invalidate all instruction caches to PoU
	 * Invalidate all branch predictors
	 */
	write_iciallu
	write_bpiall
	dsb
	isb

	/* r0 is get from SCR_GPR2, ROM did this */
	ldr	r11, [r0, #PM_INFO_ANATOP_P_OFF]
	ldr	r7, [r11, #MX6Q_ANATOP_CORE]
	and	r7, r7, #0x1f
	cmp	r7, #0x1e
	bne	ldo_check_done3
	ldr	r7, [r11, #MX6Q_ANATOP_CORE]
	orr	r7, r7, #0x1f
	str	r7, [r11, #MX6Q_ANATOP_CORE]
ldo_check_done3:
	/* Jump to v7_cpu_resume */
	ldr	lr, [r0, #PM_INFO_TEE_RESUME_OFF]

	/* Clear CORE0's entry and arg */
	ldr	r11, [r0, #PM_INFO_SRC_P_OFF]
	mov	r7, #0
	str	r7, [r11, #SRC_GPR1]
	str	r7, [r11, #SRC_GPR2]

	ldr	r3, [r0, #PM_INFO_DDR_TYPE_OFF]
	mov	r5, #0x1

	/* check whether it supports Mega/Fast off */
	ldr	r6, [r0, #PM_INFO_MMDC_NUM_OFF]
	cmp	r6, #0x0
	beq	dsm_only_resume_io
	resume_mmdc_io
	b	dsm_resume_mmdc_done
dsm_only_resume_io:
	ldr	r3, [r0, #PM_INFO_DDR_TYPE_OFF]
	resume_io
dsm_resume_mmdc_done:

	/* Enable Instruction cache and Branch predictors */
	read_sctlr r6
	orr r6, #SCTLR_Z
	add r6, r6, #SCTLR_I
	write_sctlr r6
	isb


	bx	lr
UNWIND( .fnend)
END_FUNC imx6_suspend

/**
 * @brief   Calculates and returns the suspend function size
 *
 * @retval  function size in bytes
 */
FUNC get_imx6_suspend_size, :
UNWIND( .fnstart)
	subs	r0, pc, #8
	ldr		r1, =imx6_suspend
	sub		r0, r0, r1
	bx		lr
UNWIND( .fnend)
END_FUNC get_imx6_suspend_size

/*
 * Note: VA = PA, for TEE_RAM.
 * This maybe changed in future.
 */
FUNC v7_cpu_resume, :
UNWIND( .fnstart)
/* arm_cl1_d_invbysetway */
	mov	r0, #0
	mcr	p15, 2, r0, c0, c0, 0
	isb

_inv_dcache_off:
	mov	r0, #0
_inv_nextWay:
	mov	r1, #0
_inv_nextLine:
	orr	r2, r0, r1
	mcr	p15, 0, r2, c7, c6, 2
	add	r1, r1, #1 << LINE_FIELD_OFFSET
	cmp	r1, #1 << LINE_FIELD_OVERFLOW
	bne     _inv_nextLine
	add     r0, r0, #1 << WAY_FIELD_OFFSET
	cmp     r0, #0
	bne     _inv_nextWay

	dsb
	isb

	/*
	 * No stack, scratch r0-r3
	 * TODO: Need to use specific configure, but not plat_xxx.
	 * Because plat_xx maybe changed in future, we can not rely on it.
	 * Need handle sp carefully.
	 */
	blx	plat_cpu_reset_early

	b	sm_pm_cpu_resume
UNWIND( .fnend)
END_FUNC v7_cpu_resume
