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

#define MX6_MMDC_MAPSR		0x404
#define MX6_MMDC_MPDGCTRL0		0x83c



	.section .text.psci.cpuidle

	.macro  pll_do_wait_lock
1:
	ldr	r7, [r10, r8]
	ands	r7, #0x80000000
	beq	1b

	.endm

	.macro  ccm_do_wait
2:
	ldr	r7, [r10, #0x48]
	cmp	r7, #0x0
	bne	2b

	.endm

	.macro  ccm_enter_idle

	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	/*
	 * if in audio_bus_freq_mode, skip to
	 * audio_mode low power setting.
	 */
	cmp 	r1, #0x1
	beq	audio_mode
	/*
	 * Now set DDR rate to 1MHz.
	 * DDR is from bypassed PLL2 on periph2_clk2 path.
	 * Set the periph2_clk2_podf to divide by 8.
	 */
	ldr	r6, [r10, #0x14]
	orr	r6, r6, #0x07
	str	r6, [r10, #0x14]

	/* Now set MMDC PODF to divide by 3. */
	ldr	r6, [r10, #0x14]
	bic	r6, r6,	#0x38
	orr	r6, r6, #0x10
	str	r6, [r10, #0x14]

	ccm_do_wait

	/* Set the AHB to 3MHz. AXI to 3MHz. */
	ldr	r6, [r10, #0x14]
	/*r12 stores the origin AHB podf value */
	mov	r12, r6
	orr	r6, r6, #0x1c00
	orr	r6, r6, #0x70000
	str	r6, [r10, #0x14]

	ccm_do_wait

	/* Now set ARM to 24MHz.
	 * Move ARM to be sourced from step_clk
	 * after setting step_clk to 24MHz.
	 */
	ldr	r6, [r10, #0x0c]
	bic	r6, r6, #0x100
	str	r6, [r10, #0xc]
	/*Now pll1_sw_clk to step_clk */
	ldr	r6, [r10, #0x0c]
	orr	r6, r6, #0x4
	str	r6, [r10, #0x0c]

	/* Bypass PLL1 and power it down */
	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	ldr	r6, =(1 << 16)
	orr	r6, r6, #0x1000
	str	r6, [r10, #0x04]

	/*
	 * Set the ARM PODF to divide by 8.
	 * IPG is at 1.5MHz here, we need ARM to
	 * run at the 12:5 ratio (WAIT mode issue).
	 */
	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	ldr	r11, [r10, #0x10]
	ldr	r6, =0x07
	str	r6, [r10, #0x10]

	ccm_do_wait

	b	ccm_idle_done

audio_mode:
	/*
	 * MMDC is sourced from pll2_200M.
	 * Set the mmdc_podf to div by 8
	 */
	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	ldr	r6, [r10, #0x14]
	orr	r6, r6, #0x38
	str	r6, [r10, #0x14]

	ccm_do_wait

	/*
	 * ARM is sourced from pll2_pfd2_400M here.
	 * switch ARM to bypassed PLL1
	 */
	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	ldr	r6, [r10, #0x0c]
	bic	r6, r6, #0x4
	str	r6, [r10, #0xc]

	/*
	 * set the arm_podf to divide by 3
	 * as IPG is at 4MHz, we cannot run
	 * arm clk above 9.6MHz when system
	 * enter WAIT mode
	 */
	ldr	r11, [r10, #0x10]
	ldr	r6, =0x2
	str	r6, [r10, #0x10]

	ccm_do_wait

ccm_idle_done:

	.endm

	.macro  ccm_exit_idle

	/*
	 * If in audio_bus_freq_mode, skip to
	 * audio_mode ccm restore.
	 */
	cmp	r1, #0x1
	beq	audio_ccm_restore

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	/* Power up PLL1 and un-bypass it. */
	ldr	r6, =(1 << 12)
	str	r6, [r10, #0x08]

	/* Wait for PLL1 to relock */
	ldr	r8, =0x0
	pll_do_wait_lock

	ldr	r6, =(1 << 16)
	str	r6, [r10, #0x08]

	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	/* Set PLL1_sw_clk back to PLL1 */
	ldr	r6, [r10, #0x0c]
	bic	r6, r6, #0x4
	str	r6, [r10, #0x0c]

	/* Restore AHB/AXI back */
	str	r12, [r10, #0x14]

	ccm_do_wait

	/* restore mmdc back to 24MHz*/
	ldr	r6, [r10, #0x14]
	bic	r6, r6, #0x3f
	str	r6, [r10, #0x14]

	ccm_do_wait
	b	ccm_exit_done

audio_ccm_restore:
	/* move arm clk back to pll2_pfd2_400M */
	ldr	r6, [r10, #0xc]
	orr	r6, r6, #0x4
	str	r6, [r10, #0xc]

	/* restore mmdc podf */
	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	ldr	r6, [r10, #0x14]
	bic	r6, r6, #0x38
	orr	r6, #0x8
	str	r6, [r10, #0x14]

	ccm_do_wait

ccm_exit_done:

	.endm

	.macro check_pll_state

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	/*
	 * Check whether any PLL is enabled, as only when
	 * there is no PLLs enabled, 2p5 can be off and
	 * only enable the weak one. PLL1 will be powered
	 * down late, so no need to check PLL1 state.
	 */

	/* sys PLL2 */
	ldr	r6, [r10, #0x30]
	ands r6, r6, #(1 << 31)
	bne	1f

	/* usb PLL3 */
	ldr	r6, [r10, #0x10]
	ands	r6, r6, #(1 << 31)
	bne	1f

	/* audio PLL4 */
	ldr	r6, [r10, #0x70]
	ands	r6, r6, #(1 << 31)
	bne	1f

	/* video PLL5 */
	ldr	r6, [r10, #0xa0]
	ands	r6, r6, #(1 << 31)
	bne	1f

	/* enet PLL6 */
	ldr	r6, [r10, #0xe0]
	ands	r6, r6, #(1 << 31)
	bne	1f

	/* usb host PLL7 */
	ldr	r6, [r10, #0x20]
	ands	r6, r6, #(1 << 31)
	bne	1f

	ldr	r4, =0x1
	b	check_done
1:
	ldr	r4, =0x0

check_done:
	.endm

	.macro  anatop_enter_idle

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	cmp	r4, #0x0
	beq	anatop_enter_done

	/* Disable 1p1 brown out. */
	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	ldr	r6, [r10, #0x110]
	bic	r6, r6, #0x2
	str	r6, [r10, #0x110]
	/*
	 * Set the OSC bias current to -37.5%
	 * to drop the power on VDDHIGH.
	 */
	ldr	r6, [r10, #0x150]
	orr	r6, r6, #0xc000
	str	r6, [r10, #0x150]

	/*
	 * if the usb VBUS wakeup is enabled, skip
	 * disable main 2p5.
	 */
	cmp	r2, #0x1
	beq	anatop_enter_done

	/* Enable the week 2p5 */
	ldr	r6, [r10, #0x130]
	orr	r6, r6, #0x40000
	str	r6, [r10, #0x130]

	/* Disable main 2p5. */
	ldr	r6, [r10, #0x130]
	bic	r6, r6, #0x1
	str	r6, [r10, #0x130]

	/*
	 * Cannot disable regular bandgap
	 * in LDO-enable mode. The bandgap
	 * is required for ARM-LDO to regulate
	 * the voltage.
	 */
	ldr	r6, [r10, #0x140]
	and	r6, r6, #0x1f
	cmp	r6, #0x1f
	bne	anatop_enter_done

	/* Enable low power bandgap */
	ldr	r6, [r10, #0x260]
	orr	r6, r6, #0x20
	str	r6, [r10, #0x260]

	/*
	 * Turn off the bias current
	 * from the regular bandgap.
	 */
	ldr	r6, [r10, #0x260]
	orr	r6, r6, #0x80
	str	r6, [r10, #0x260]

	/*
	 * Clear the REFTTOP+SELFBIASOFF,
	 * self_bais circuit of the band gap.
	 * Per RM, should be cleared when
	 * band gap is powered down.
	 */
	ldr	r6, [r10, #0x150]
	bic	r6, r6, #0x8
	str	r6, [r10, #0x150]

	/* Power down the regular bandgap */
	ldr	r6, [r10, #0x150]
	orr	r6, r6, #0x1
	str	r6, [r10, #0x150]
anatop_enter_done:

	.endm

	.macro  anatop_exit_idle

	ldr	r10, [r0, #PM_INFO_ANATOP_V_OFF]
	cmp	r4, #0x0
	beq	skip_anatop_restore

	cmp	r2, #0x1
	beq	ldo2p5_not_disabled
	/*
	 * Regular bandgap will not be disabled
	 * in LDO-enabled mode as it is required
	 * for ARM-LDO to reguulate the voltage.
	 */
	ldr	r6, [r10, #0x140]
	and	r6, r6, #0x1f
	cmp	r6, #0x1f
	bne	skip_bandgap_restore

	/* Power up the regular bandgap */
	ldr	r6, [r10, #0x150]
	bic	r6, r6, #0x1
	str	r6, [r10, #0x150]

	/* wait for bandgap stable */
3:
	ldr	r6, [r10, #0x150]
	and	r6, r6, #0x80
	cmp	r6, #0x80
	bne	3b

	/* now disable bandgap self-bias circuit */
	ldr	r6, [r10, #0x150]
	orr	r6, r6, #0x8
	str	r6, [r10, #0x150]

	/* Turn on the bias current
	 * from the regular bandgap.
	 */
	ldr	r6, [r10, #0x260]
	bic	r6, r6, #0x80
	str	r6, [r10, #0x260]

	/* Disable the low power bandgap */
	ldr	r6, [r10, #0x260]
	bic	r6, r6, #0x20
	str	r6, [r10, #0x260]

skip_bandgap_restore:
	/* Enable main 2p5. */
	ldr	r6, [r10, #0x130]
	orr	r6, r6,	#0x1
	str	r6, [r10, #0x130]

	/* Ensure the 2p5 is up */
5:
	ldr	r6, [r10, #0x130]
	and	r6, r6, #0x20000
	cmp	r6, #0x20000
	bne	5b

	/* Disable the weak 2p5 */
	ldr	r6, [r10, #0x130]
	bic	r6, r6, #0x40000
	str	r6, [r10, #0x130]

ldo2p5_not_disabled:
	/*
	 * Set the OSC bias current to max
	 * value for normal operation.
	 */
	ldr	r6, [r10, #0x150]
	bic	r6, r6, #0xc000
	str	r6, [r10, #0x150]

	/* Enable 1p1 brown out, */
	ldr	r6, [r10, #0x110]
	orr	r6, r6, #0x2
	str	r6, [r10, #0x110]

skip_anatop_restore:

	.endm

	.macro  disable_l1_dcache

	/* disable d-cache */
	mrc	p15, 0, r7, c1, c0, 0
	bic	r7, r7, #(1 << 2)
	mcr	p15, 0, r7, c1, c0, 0

	dsb
	isb

	.endm

	.macro  mmdc_enter_dvfs_mode

	/* disable automatic power saving. */
	ldr	r7, [r10, #MX6_MMDC_MAPSR]
	orr	r7, r7, #0x1
	str	r7, [r10, #MX6_MMDC_MAPSR]

	/* disable power down timer */
	ldr	r7, [r10, #0x04]
	bic	r7, r7, #0xff00
	str	r7, [r10, #0x04]

	/* Make the DDR explicitly enter self-refresh. */
	ldr	r7, [r10, #MX6_MMDC_MAPSR]
	orr	r7, r7, #(1 << 21)
	str	r7, [r10, #MX6_MMDC_MAPSR]

poll_dvfs_set:
	ldr	r7, [r10, #MX6_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	beq	poll_dvfs_set

	/* set SBS step-by step mode */
	ldr	r7, [r10, #0x410]
	orr	r7, r7, #0x100
	str	r7, [r10, #0x410]

	.endm

	.macro  resume_mmdc
	/* restore MMDC IO */
	ldr	r10, [r0, #PM_INFO_IOMUXC_V_OFF]

	ldr	r6, [r0, #PM_INFO_MMDC_IO_NUM_OFF]
	ldr	r7, =PM_INFO_MMDC_IO_VAL_OFF
	add	r7, r7, r0
6:
	ldr	r8, [r7], #0x4
	ldr	r9, [r7], #0x4
	str	r9, [r10, r8]
	add	r7, r7, #0x4
	subs	r6, r6, #0x1
	bne	6b

	/*
	 * Need to reset the FIFO to avoid MMDC lockup
	 * caused because of floating/changing the
	 * configuration of many DDR IO pads.
	 */
	ldr	r10, [r0, #PM_INFO_MMDC0_V_OFF]
	/* reset read FIFO, RST_RD_FIFO */
	ldr	r7, =MX6_MMDC_MPDGCTRL0
	ldr	r6, [r10, r7]
	orr	r6, r6, #(1 << 31)
	str	r6, [r10, r7]
7:
	ldr	r6, [r10, r7]
	ands	r6, r6, #(1 << 31)
	bne	7b

	/* reset FIFO a second time */
	ldr	r7, =MX6_MMDC_MPDGCTRL0
	ldr	r6, [r10, r7]
	orr	r6, r6, #(1 << 31)
	str	r6, [r10, r7]
8:
	ldr	r6, [r10, r7]
	ands	r6, r6, #(1 <<31)
	bne	8b

	ldr	r10, [r0, #PM_INFO_MMDC0_V_OFF]
	/* Let DDR out of self-refresh */
	ldr	r7, [r10, #MX6_MMDC_MAPSR]
	bic	r7, r7, #(1 << 21)
	str	r7, [r10, #MX6_MMDC_MAPSR]
9:
	ldr	r7, [r10, #MX6_MMDC_MAPSR]
	ands	r7, r7, #(1 << 25)
	bne	9b

	/* enable power down timer */
	ldr	r7, [r10, #0x04]
	orr	r7, r7, #0x5500
	str	r7, [r10, #0x04]

	/* enable DDR auto power saving */
	ldr	r7, [r10, #MX6_MMDC_MAPSR]
	bic	r7, r7,	#0x1
	str	r7, [r10, #MX6_MMDC_MAPSR]

	/* Clear SBS - unblock DDR accesses */
	ldr	r7, [r10, #0x410]
	bic	r7, r7, #0x100
	str	r7, [r10, #0x410]

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

	/* Disable Branch Prediction, Z bit in SCTLR. */
	read_sctlr r6
	bic	r6, r6, #0x800
	write_sctlr r6

	/* Flush the BTAC. */
	write_bpiallis

	ldr	r6, =iram_tlb_phys_addr
	ldr	r7, [r6]

	dsb
	isb

	/* Store the IRAM table in TTBR1 */
	write_ttbr1 r7
	write_ttbr0 r7

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

.extern iram_tlb_phys_addr

/*
 * imx6sl_low_power_wfi code
 * r0: wfi code base address
 * r1: audio_bus_freq mode stat
 * r2: vbus_ldo status
 * r4: used for store the PLLs state
 * r11: used for saving the ARM_PODF origin value
 * r12: used for saving AHB_PODF origin value
 */
	.align 3
FUNC imx6sl_low_power_idle, :
UNWIND( .fnstart)
	push {r4-r12}

	tlb_set_to_ocram
	disable_l1_dcache

#ifdef CFG_PL310
	/* sync L2 */
	ldr	r10, [r0, #PM_INFO_PL310_V_OFF]
	/* Wait for background operations to complete. */
wait_for_l2_idle:
	ldr	r6, [r10, #0x730]
	cmp	r6, #0x0
	bne	wait_for_l2_idle

	mov	r6, #0x0
	str	r6, [r10, #0x730]
	/* disable L2 */
	str	r6, [r10, #0x100]

	dsb
	isb
#endif

	/* parse the ldo and audio mode state */
	ldr	r10, [r0, #PM_INFO_IDLE_STATE]
	and	r2, r10, #(1 << 1) /* ldo status */
	lsr	r2, r2, #0x1
	and	r1, r10, #(1 << 2) /* audio mode status */
	lsr	r1, r1, #0x2

	/* make sure MMDC in self-refresh */
	ldr	r10, [r0, #PM_INFO_MMDC0_V_OFF]
	mmdc_enter_dvfs_mode
	/* save DDR IO settings and set to LPM mode*/
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
	add	r8, r8, #0x4
	subs	r7, r7, #0x1
	bne	save_and_set_mmdc_io_lpm

	/* check the PLLs lock state */
	check_pll_state

	ccm_enter_idle
	/* if in audio low power mode, no
	 * need to do anatop setting.
	 */
	cmp	r1, #0x1
	beq	do_wfi
	anatop_enter_idle
do_wfi:
	wfi
	/*
	 * Add these nops so that the
	 * prefetcher will not try to get
	 * any instrutions from DDR.
	 * The prefetch depth is about 23
	 * on A9, so adding 25 nops.
	 */
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

	/*
	 * restore the ARM PODF first to speed
	 * up the restore procedure
	 */
	ldr	r10, [r0, #PM_INFO_CCM_V_OFF]
	/* Restore arm_clk_podf */
	str	r11, [r10, #0x10]
	ccm_do_wait

	/*
	 * if in audio low power mode, skip
	 * restore the anatop setting.
	 */
	cmp	r1, #0x1
	beq 	skip_analog_restore
	anatop_exit_idle

skip_analog_restore:
	ccm_exit_idle
	resume_mmdc

	/* enable d-cache */
	mrc	p15, 0, r7, c1, c0, 0
	orr	r7, r7, #(1 << 2)
	mcr	p15, 0, r7, c1, c0, 0

#ifdef CFG_PL310
	ldr	r10, [r0, #PM_INFO_PL310_V_OFF]
	mov	r7, #0x1
	/* enable L2 */
	str	r7, [r10, #0x100]
#endif
	tlb_back_to_ddr

	/* Restore register */
	pop	{r4 - r12}
	mov	pc, lr

	/*
	 * Add ltorg here to ensure that all
	 * literals are stored here and are
	 * within the text space.
	 */
	.ltorg
mx6sl_lpm_wfi_end:
UNWIND( .fnend)
END_FUNC imx6sl_low_power_idle
