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
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_def.h>

	.section .text.psci.cpuidle

	.macro	pll_do_wait_lock
1:
	ldr	r7, [r10, r8]
	ands	r7, #0x80000000
	beq	1b

	.endm

	.macro	ccm_do_wait
2:
	ldr	r7, [r10, #0x48]
	cmp	r7, #0x0
	bne	2b

	.endm

	.macro	ccm_enter_idle

	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]

	/* set ahb to 3MHz */
	ldr	r7, [r10, #0x14]
	orr	r7, r7, #0x1c00
	str	r7, [r10, #0x14]

	/* set perclk to 6MHz */
	ldr	r7, [r10, #0x1c]
	bic	r7, r7, #0x3f
	orr	r7, r7, #0x3
	str	r7, [r10, #0x1c]

	/* set mmdc to 1MHz, periph2_clk2 need to be @8MHz */
	ldr	r7, [r10, #0x14]
	orr     r7, r7, #0x2
	orr	r7, r7, #(0x7 << 3)
	str	r7, [r10, #0x14]

	ccm_do_wait

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]

	/* bypass PLL1 output to OSC */
	ldr	r7, [r10]
	orr	r7, r7, #(0x1 << 16)
	str	r7, [r10]

	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]

	/* set pll1_sw to from pll1 main */
	ldr	r7, [r10, #0xc]
	bic	r7, r7, #0x4
	str	r7, [r10, #0xc]

	/* set step from osc */
	ldr	r7, [r10, #0xc]
	bic	r7, r7, #0x100
	str	r7, [r10, #0xc]

	/* set pll1_sw to from step */
	ldr	r7, [r10, #0xc]
	orr	r7, r7, #0x4
	str	r7, [r10, #0xc]

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]

	/* Disable PLL1 bypass output */
	ldr	r7, [r10]
	bic	r7, r7, #0x12000
	str	r7, [r10]

	/*
	 * disable pll2, suppose when system enter low
	 * power idle mode, only 396MHz pfd needs pll2,
	 * now we switch arm clock to OSC, we can disable
	 * pll2 now, gate pll2_pfd2 first.
	 */
	ldr	r7, [r10, #0x100]
	orr	r7, #0x800000
	str	r7, [r10, #0x100]

	ldr	r7, [r10, #0x30]
	orr	r7, r7, #0x1000
	bic	r7, r7, #0x2000
	str	r7, [r10, #0x30]

	.endm

	.macro	ccm_exit_idle

	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	ldrne	r10, [r0, #PM_INFO_ANATOP_P_OFF]

	/* enable pll2 and pll2_pfd2 */
	ldr	r7, [r10, #0x30]
	bic	r7, r7, #0x1000
	orr	r7, r7, #0x2000
	str	r7, [r10, #0x30]

	ldr	r8, =0x30
	pll_do_wait_lock

	ldr	r7, [r10, #0x100]
	bic	r7, #0x800000
	str	r7, [r10, #0x100]

	/* enable PLL1 bypass output */
	ldr	r7, [r10]
	orr	r7, r7, #0x12000
	str	r7, [r10]

	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_CCM_V_OFF]
	ldrne	r10, [r0, #PM_INFO_CCM_P_OFF]

	/* set perclk back to 24MHz */
	ldr	r7, [r10, #0x1c]
	bic	r7, r7, #0x3f
	str	r7, [r10, #0x1c]

	/* set mmdc back to 24MHz */
	ldr	r7, [r10, #0x14]
	bic	r7, r7, #0x7
	bic	r7, r7, #(0x7 << 3)
	str	r7, [r10, #0x14]

	/* set ahb div back to 24MHz */
	ldr	r7, [r10, #0x14]
	bic	r7, r7, #0x1c00
	str	r7, [r10, #0x14]

	ccm_do_wait

	/* set pll1_sw to from pll1 main */
	ldr	r7, [r10, #0xc]
	bic	r7, r7, #0x4
	str	r7, [r10, #0xc]

	/* set step from pll2_pfd2 */
	ldr	r7, [r10, #0xc]
	orr	r7, r7, #0x100
	str	r7, [r10, #0xc]

	/* set pll1_sw to from step */
	ldr	r7, [r10, #0xc]
	orr	r7, r7, #0x4
	str	r7, [r10, #0xc]

	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	ldrne	r10, [r0, #PM_INFO_ANATOP_P_OFF]

	/* Unbypass PLL1 */
	ldr	r7, [r10]
	bic	r7, r7, #(0x1 << 16)
	str	r7, [r10]

	.endm

	.macro	anatop_enter_idle

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]

	/*
	 * check whether any PLL is enabled, as only when
	 * there is no PLLs enabled, 2P5 and 1P1 can be
	 * off and only enable weak ones.
	 */

	/* arm pll1 */
	ldr	r7, [r10, #0]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* sys pll2 */
	ldr	r7, [r10, #0x30]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* usb pll3 */
	ldr	r7, [r10, #0x10]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* audio pll4 */
	ldr	r7, [r10, #0x70]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* vidio pll5 */
	ldr	r7, [r10, #0xa0]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* enet pll6 */
	ldr	r7, [r10, #0xe0]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* usb host pll7 */
	ldr	r7, [r10, #0x20]
	ands	r7, r7, #(1 << 31)
	bne	10f

	/* enable weak 2P5 and turn off regular 2P5 */
	ldr	r7, [r10, #0x130]
	orr	r7, r7, #0x40000
	str	r7, [r10, #0x130]
	bic	r7, r7, #0x1
	str	r7, [r10, #0x130]

	/* enable weak 1p1 and turn off regular 1P1 */
	ldr	r7, [r10, #0x110]
	orr	r7, r7, #0x40000
	str	r7, [r10, #0x110]
	bic	r7, r7, #0x1
	str	r7, [r10, #0x110]

	/* check whether ARM LDO is bypassed */
	ldr	r7, [r10, #0x140]
	and	r7, r7, #0x1f
	cmp	r7, #0x1f
	bne	10f

	/* low power band gap enable */
	ldr	r7, [r10, #0x270]
	orr	r7, r7, #0x20
	str	r7, [r10, #0x270]

	/* turn off the bias current from the regular bandgap */
	ldr	r7, [r10, #0x270]
	orr	r7, r7, #0x80
	str	r7, [r10, #0x270]

	/*
	 * clear the REFTOP_SELFBIASOFF,
	 * self-bias circuit of the band gap.
	 * Per RM, should be cleared when
	 * band gap is powered down.
	 */
	ldr	r7, [r10, #0x150]
	bic	r7, r7, #0x8
	str	r7, [r10, #0x150]

	/* turn off regular bandgap */
	ldr	r7, [r10, #0x150]
	orr	r7, r7, #0x1
	str	r7, [r10, #0x150]

	/* switch to RC-OSC */
	ldr	r7, [r10, #0x270]
	orr	r7, r7, #0x10
	str	r7, [r10, #0x270]

	/* turn off XTAL-OSC */
	ldr	r7, [r10, #0x150]
	orr	r7, r7, #0x40000000
	str	r7, [r10, #0x150]
10:
	/* lower OSC current by 37.5% */
	ldr	r7, [r10, #0x150]
	orr	r7, r7, #0x6000
	str	r7, [r10, #0x150]

	/* disconnect vdd_high_in and vdd_snvs_in */
	ldr	r7, [r10, #0x150]
	orr	r7, r7, #0x1000
	str	r7, [r10, #0x150]

	.endm

	.macro anatop_exit_idle

	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	ldrne	r10, [r0, #PM_INFO_ANATOP_P_OFF]

	/* increase OSC current to normal */
	ldr	r7, [r10, #0x150]
	bic	r7, r7, #0x6000
	str	r7, [r10, #0x150]

	/* turn on XTAL-OSC and detector */
	ldr	r7, [r10, #0x150]
	bic	r7, r7, #0x40000000
	orr	r7, r7, #0x10000
	str	r7, [r10, #0x150]

	/* wait for XTAL stable */
14:
	ldr	r7, [r10, #0x150]
	ands	r7, r7, #0x8000
	beq	14b

	/* switch to XTAL-OSC */
	ldr	r7, [r10, #0x270]
	bic	r7, r7, #0x10
	str	r7, [r10, #0x270]

	/* turn off XTAL-OSC detector */
	ldr	r7, [r10, #0x150]
	bic	r7, r7, #0x10000
	str	r7, [r10, #0x150]
15:
	/* check whether we need to enable 2P5/1P1 */
	ldr	r7, [r10, #0x110]
	ands	r7, r7, #0x40000
	beq	11f

	/* check whether ARM LDO is bypassed */
	ldr	r7, [r10, #0x140]
	and	r7, r7, #0x1f
	cmp	r7, #0x1f
	bne	12f

	/* turn on regular bandgap and wait for stable */
	ldr	r7, [r10, #0x150]
	bic	r7, r7, #0x1
	str	r7, [r10, #0x150]
13:
	ldr	r7, [r10, #0x150]
	ands	r7, #0x80
	beq	13b

	/*
	 * set the REFTOP_SELFBIASOFF,
	 * self-bias circuit of the band gap.
	 */
	ldr     r7, [r10, #0x150]
	orr     r7, r7, #0x8
	str     r7, [r10, #0x150]

	/* turn on the bias current from the regular bandgap */
	ldr	r7, [r10, #0x270]
	bic	r7, r7, #0x80
	str	r7, [r10, #0x270]

	/* low power band gap disable */
	ldr	r7, [r10, #0x270]
	bic	r7, r7, #0x20
	str	r7, [r10, #0x270]
12:
	/* enable regular 2P5 and turn off weak 2P5 */
	ldr	r7, [r10, #0x130]
	orr	r7, r7, #0x1
	str	r7, [r10, #0x130]

	/* Ensure the 2P5 is up. */
3:
	ldr	r7, [r10, #0x130]
	ands	r7, r7, #0x20000
	beq	3b
	ldr	r7, [r10, #0x130]
	bic	r7, r7, #0x40000
	str	r7, [r10, #0x130]

	/* enable regular 1p1 and turn off weak 1P1 */
	ldr	r7, [r10, #0x110]
	orr	r7, r7, #0x1
	str	r7, [r10, #0x110]
4:
	ldr	r7, [r10, #0x110]
	ands	r7, r7, #0x20000
	beq	4b
	ldr	r7, [r10, #0x110]
	bic	r7, r7, #0x40000
	str	r7, [r10, #0x110]
11:
	.endm

	.macro	disable_l1_dcache

	/*
	 * Flush all data from the L1 data cache before disabling
	 * SCTLR.C bit.
	 */
	push    {r0 - r10, lr}
	mov	r0, #DCACHE_OP_CLEAN_INV
	ldr	r1, =dcache_op_all
	mov	lr, pc
	bx	r1
	pop     {r0 - r10, lr}

	/* disable d-cache */
	read_sctlr r7
	bic	r7, r7, #0x4
	write_sctlr r7
	dsb
	isb

	push    {r0 - r10, lr}
	mov	r0, #DCACHE_OP_CLEAN_INV
	ldr	r1, =dcache_op_all
	mov	lr, pc
	bx	r1
	pop     {r0 - r10, lr}

	.endm

	.macro mmdc_enter_dvfs_mode

	/* disable automatic power savings. */
	ldr	r7, [r10, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #0x1
	str	r7, [r10, #MX6Q_MMDC_MAPSR]

	/* disable power down timer */
	ldr	r7, [r10, #0x4]
	bic	r7, r7, #0xff00
	str	r7, [r10, #0x4]

	/* make the DDR explicitly enter self-refresh. */
	ldr	r7, [r10, #MX6Q_MMDC_MAPSR]
	orr	r7, r7, #(1 << 21)
	str	r7, [r10, #MX6Q_MMDC_MAPSR]
5:
	ldr	r7, [r10, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	beq	5b

	.endm

	.macro	resume_mmdc

	/* restore MMDC IO */
	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_IOMUXC_V_OFF]
	ldrne	r10, [r0, #PM_INFO_IOMUXC_P_OFF]

	ldr	r6, [r0, #PM_INFO_MMDC_IO_NUM_OFF]
	ldr	r7, =PM_INFO_MMDC_IO_VAL_OFF
	add	r7, r7, r0
6:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	add	r7, r7, #0x4
	str	r9, [r10, r8]
	subs	r6, r6, #0x1
	bne	6b

	cmp	r5, #0x0
	ldreq	r10, [r0, #PM_INFO_MMDC0_V_OFF]
	ldrne	r10, [r0, #PM_INFO_MMDC0_P_OFF]

	/* reset read FIFO, RST_RD_FIFO */
	ldr	r7, =MX6Q_MMDC_MPDGCTRL0
	ldr	r6, [r10, r7]
	orr	r6, r6, #(1 << 31)
	str	r6, [r10, r7]
7:
	ldr	r6, [r10, r7]
	ands	r6, r6, #(1 << 31)
	bne	7b

	/* reset FIFO a second time */
	ldr	r6, [r10, r7]
	orr	r6, r6, #(1 << 31)
	str	r6, [r10, r7]
8:
	ldr	r6, [r10, r7]
	ands	r6, r6, #(1 << 31)
	bne	8b

	/* let DDR out of self-refresh */
	ldr	r7, [r10, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #(1 << 21)
	str	r7, [r10, #MX6Q_MMDC_MAPSR]
9:
	ldr	r7, [r10, #MX6Q_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	bne	9b

	/* enable power down timer */
	ldr	r7, [r10, #0x4]
	orr	r7, r7, #0x5500
	str	r7, [r10, #0x4]

	/* enable DDR auto power saving */
	ldr	r7, [r10, #MX6Q_MMDC_MAPSR]
	bic	r7, r7, #0x1
	str	r7, [r10, #MX6Q_MMDC_MAPSR]

	.endm

	.macro	tlb_set_to_ocram

	/* save ttbr */
	read_ttbr1 r7
	str	r7, [r0, #PM_INFO_TTBR1_OFF]

	read_ttbr0 r7
	str	r7, [r0, #PM_INFO_TTBR0_OFF]

	/*
	 * To ensure no page table walks occur in DDR, we
	 * have a another page table stored in IRAM that only
	 * contains entries pointing to IRAM, AIPS1 and AIPS2.
	 * We need to set the TTBR1 to the new IRAM TLB.
	 * Do the following steps:
	 * 1. Flush the Branch Target Address Cache (BTAC)
	 * 2. Set TTBR1 to point to IRAM page table.
	 * 3. Disable page table walks in TTBR0 (PD0 = 1)
	 * 4. Set TTBR0.N=1, implying 0-2G is translated by TTBR0
	 *     and 2-4G is translated by TTBR1.
	 */

	ldr	r6, =iram_tlb_phys_addr
	ldr	r7, [r6]

	/* Flush the BTAC. */
	write_bpiallis

	/* Disable Branch Prediction, Z bit in SCTLR. */
	read_sctlr r6
	bic	r6, r6, #0x800
	write_sctlr r6

	dsb
	isb

	/* Store the IRAM table in TTBR1/TTBR0 */
	write_ttbr1 r7
	write_ttbr0 r7

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

	.macro	tlb_back_to_ddr

	/* Restore the TTBCR */

	dsb
	isb

	/* Read TTBCR and set PD0=0, N = 0 */
	read_ttbcr r6
	bic	r6, r6, #0x10
	write_ttbcr r6

	dsb
	isb

	/* flush the TLB */
	write_tlbiallis

	dsb
	isb

	/* Enable Branch Prediction, Z bit in SCTLR. */
	read_sctlr r6
	orr	r6, r6, #0x800
	write_sctlr r6

	/* Flush the Branch Target Address Cache (BTAC) */
	write_bpiallis

	/* restore ttbr */
	ldr	r6, [r0, #PM_INFO_TTBR1_OFF]
	write_ttbr1 r6
	ldr	r6, [r0, #PM_INFO_TTBR0_OFF]
	write_ttbr0 r6
	isb

	.endm

/* imx6ul_low_power_idle */

	.align 3

FUNC imx6ul_low_power_idle, :
UNWIND( .fnstart)
	push	{r4 - r10}

	ldr	r1, [r0, #PM_INFO_PBASE_OFF]
	ldr	r2, [r0, #PM_INFO_INFO_SIZE_OFF]

	/*
	 * R3 points the resume address that set in SRC GPR1
	 */
	ldr	r5, =imx6ul_low_power_idle
	ldr	r6, =wakeup
	sub	r6, r6, r5
	add	r8, r1, r2
	add	r3, r8, r6

	ldr	r10, [r0, #PM_INFO_SRC_V_OFF]
	str	r3, [r10, #0x20]
	str	r1, [r10, #0x24]

	ldr	r10, [r0, #PM_INFO_GPC_V_OFF]
	ldr	r7, =0x1
	str	r7, [r10, #0x2a0]

	disable_l1_dcache

	tlb_set_to_ocram

	ldr	r10, [r0, #PM_INFO_MMDC0_V_OFF]
	mmdc_enter_dvfs_mode

	ldr	r10, [r0, #PM_INFO_IOMUXC_V_OFF]
	ldr	r6, =0x0
	ldr	r7, [r0, #PM_INFO_MMDC_IO_NUM_OFF]
	ldr	r8, =PM_INFO_MMDC_IO_VAL_OFF
	add	r8, r8, r0

save_and_set_mmdc_io_lpm:
	ldr	r9, [r8], #0x4
	ldr	r5, [r10, r9]
	str	r6, [r10, r9]
	str	r5, [r8], #0x4
	/* We reuse the structure for suspend/resume,
	 * the step is 12 bytes.
	 */
	add	r8, r8, #0x4
	subs	r7, r7, #0x1
	bne	save_and_set_mmdc_io_lpm

	mov	r5, #0x0
	ccm_enter_idle
	anatop_enter_idle

	/*
	 * Mask all GPC interrupts before enabling the RBC counters
	 * to avoid the counter starting too early if an interrupt is
	 * already pending.
	 */
	 ldr	r10, [r0, #PM_INFO_GPC_V_OFF]
	 ldr	r4, [r10, #MX6Q_GPC_IMR1]
	 ldr	r5, [r10, #MX6Q_GPC_IMR2]
	 ldr	r6, [r10, #MX6Q_GPC_IMR3]
	 ldr	r7, [r10, #MX6Q_GPC_IMR4]

	 ldr	r3, =0xffffffff
	 str	r3, [r10, #MX6Q_GPC_IMR1]
	 str	r3, [r10, #MX6Q_GPC_IMR2]
	 str	r3, [r10, #MX6Q_GPC_IMR3]
	 str	r3, [r10, #MX6Q_GPC_IMR4]

	 /*
	  * Enable the RBC bypass counter here
	  * to hold off the interrupts. RBC counter
	  * = 4 (120us). With this setting, the latency
	  * from wakeup interrupt to ARM power up
	  * is ~130us
	  */

	  ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	  ldr	r3, [r10, #MX6Q_CCM_CCR]
	  bic	r3, r3, #(0x3f << 21)
	  orr	r3, r3, #(0x20 << 21)
	  str	r3, [r10, #MX6Q_CCM_CCR]

	  ldr	r3, [r10, #MX6Q_CCM_CCR]
	  orr	r3, r3, #(0x1 << 27)
	  str	r3, [r10, #MX6Q_CCM_CCR]

	  /* unmask all the GPC interrupts. */
	  ldr     r10, [r0, #PM_INFO_GPC_V_OFF]
	  str	r4, [r10, #MX6Q_GPC_IMR1]
	  str	r5, [r10, #MX6Q_GPC_IMR2]
	  str	r6, [r10, #MX6Q_GPC_IMR3]
	  str	r7, [r10, #MX6Q_GPC_IMR4]

	/*
	 * now delay for a short while (3usec)
	 * ARM is at 24MHz at this point
	 * so a short loop should be enough.
	 * this delay is required to ensure that
	 * the RBC counter can start counting in
	 * case an interrupt is already pending
	 * or in case an interrupt arrives just
	 * as ARM is about to assert DSM_request.
	 */
	ldr	r4, =50
rbc_loop:
	subs	r4, r4, #0x1
	bne	rbc_loop

	wfi

	nop
	nop
	nop
	nop
	nop

	nop
	nop
	nop
	nop
	nop

	nop
	nop
	nop
	nop
	nop

	nop
	nop
	nop
	nop
	nop

	nop
	nop
	nop
	nop
	nop

	mov	r5, #0x0
	anatop_exit_idle
	ccm_exit_idle

	/* clear ARM power gate setting */
	ldr	r10, [r0, #PM_INFO_GPC_V_OFF]
	ldr	r7, =0x0
	str	r7, [r10, #0x2a0]

	resume_mmdc
	/* enable d-cache */
	mrc	p15, 0, r7, c1, c0, 0
	orr	r7, r7, #(1 << 2)
	mcr	p15, 0, r7, c1, c0, 0

	tlb_back_to_ddr

	/* Restore registers */
	pop	{r4 - r10}
	bx	lr

wakeup:
	/* Not use arm_cl1_i_inv_all, we are in ocram now */
	/* Invalidate Entire Instruction Cache */
	write_icialluis
	DSB
	/* Flush entire branch target cache */
	write_bpiallis
	DSB
	ISB

	/* switch monitor mode */
	mov	r3, #0x16
	mov	r4, #((1 << 6) | (1 << 7))
	orr	r3, r3, r4
	msr	cpsr, r3
	nop
	nop
	nop

	/* enable the Icache and branch prediction */
	mov	r1, #0x1800
	write_sctlr r1
	isb

	/* get physical resume address from pm_info. */
	ldr	lr, [r0, #PM_INFO_TEE_RESUME_OFF]
	/* clear core0's entry and parameter */
	ldr	r10, [r0, #PM_INFO_SRC_P_OFF]
	mov	r7, #0x0
	str	r7, [r10, #MX6Q_SRC_GPR1]
	str	r7, [r10, #MX6Q_SRC_GPR2]

	/* clear ARM power gate setting */
	ldr	r10, [r0, #PM_INFO_GPC_P_OFF]
	ldr	r7, =0x0
	str	r7, [r10, #0x2a0]

	mov	r5, #0x1
	anatop_exit_idle
	ccm_exit_idle
	resume_mmdc

	/* Restore registers, LR may points to thumb instructions */
	bx	lr
	.ltorg
mx6ul_lpm_wfi_end:
UNWIND( .fnend)
END_FUNC imx6ul_low_power_idle
