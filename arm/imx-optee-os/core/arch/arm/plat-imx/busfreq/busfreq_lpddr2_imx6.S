/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_lpddr2_imx6.S
 *
 * @brief   Implementation of the bus frequency LPDDR2
 *          assembly function on i.MX6 devices
 */

/* Global includes */
#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/unwind.h>

/* Generated includes */
#include <generated/busfreq_imx6_defines.h>

/* Local includes */
#include "busfreq_imx6.h"

#include "busfreq_macro_imx6.S"

	.macro set_timings_below_100MHz_operation
	/* Set MMDCx_MISC[RALAT] = 2 cycles */
	ldr	r0, [r9, #MX6_MMDC_MDMISC]
	bic	r0, r0, #(0x7 << 6)
	orr	r0, r0, #(0x2 << 6)
	str	r0, [r9, #MX6_MMDC_MDMISC]

	/* Adjust LPDDR2 timmings for 24Mhz operation */
	ldr	r1, =0x03032073
	str	r1, [r9, #MX6_MMDC_MDCFG0]
	ldr	r2, =0x00020482
	str	r2, [r9, #MX6_MMDC_MDCFG1]
	ldr	r3, =0x00000049
	str	r3, [r9, #MX6_MMDC_MDCFG2]
	ldr	r4, =0x00020333
	str	r4, [r9, #MX6_MMDC_MDCFG3LP]

	/* Check if lpddr2 channel 1 is enabled */
	cmp r8, #0
	beq	skip_below_100Mhz_ch1_timings

	ldr	r0, [r8, #MX6_MMDC_MDMISC]
	bic	r0, r0, #(0x7 << 6)
	orr	r0, r0, #(0x2 << 6)
	str	r0, [r8, #MX6_MMDC_MDMISC]

	str	r1, [r8, #MX6_MMDC_MDCFG0]
	str	r2, [r8, #MX6_MMDC_MDCFG1]
	str	r3, [r8, #MX6_MMDC_MDCFG2]
	str	r4, [r8, #MX6_MMDC_MDCFG3LP]

skip_below_100Mhz_ch1_timings:

	.endm

	.macro set_timings_above_100MHz_operation
	/* Set MMDCx_MISC[RALAT] = 5 cycles */
	ldr	r0, [r9, #MX6_MMDC_MDMISC]
	bic	r0, r0, #(0x7 << 6)
	orr	r0, r0, #(0x5 << 6)
	str	r0, [r9, #MX6_MMDC_MDMISC]

	/* Adjust LPDDR2 timmings for 400Mhz operation */
	ldr	r1, =0x33374133
	str	r1, [r9, #MX6_MMDC_MDCFG0]
	ldr	r2, =0x00100A82
	str	r2, [r9, #MX6_MMDC_MDCFG1]
	ldr	r3, =0x00000093
	str	r3, [r9, #MX6_MMDC_MDCFG2]
	ldr	r4, =0x001A0889
	str	r4, [r9, #MX6_MMDC_MDCFG3LP]

	/* Check if lpddr2 channel 1 is enabled */
	cmp r8, #0
	beq	skip_above_100Mhz_ch1_timings

	ldr	r0, [r8, #MX6_MMDC_MDMISC]
	bic	r0, r0, #(0x7 << 6)
	orr	r0, r0, #(0x5 << 6)
	str	r0, [r8, #MX6_MMDC_MDMISC]

	str	r1, [r8, #MX6_MMDC_MDCFG0]
	str	r2, [r8, #MX6_MMDC_MDCFG1]
	str	r3, [r8, #MX6_MMDC_MDCFG2]
	str	r4, [r8, #MX6_MMDC_MDCFG3LP]

skip_above_100Mhz_ch1_timings:

	.endm

	.macro	mmdc_clk_lower_100MHz

	is_mx6qp
	bne	1f
	set_timings_below_100MHz_operation

1:
	/*
	 * Prior to reducing the DDR frequency (at 528/400 MHz),
	 * read the Measure unit count bits (MU_UNIT_DEL_NUM)
	 */
	ldr r5, =MX6_MMDC_MPMUR0
	ldr	r0, [r9, r5]
	/* Original MU unit count */
	mov	r0, r0, LSR #16
	ldr	r1, =0x3FF
	and	r0, r0, r1
	/* Original MU unit count * 2 */
	mov	r2, r0, LSL #1
	/*
	 * Bypass the automatic measure unit when below 100 MHz
	 * by setting the Measure unit bypass enable bit (MU_BYP_EN)
	 */
	ldr	r0, [r9, r5]
	orr	r0, r0, #0x400
	str	r0, [r9, r5]
	/*
	 * Double the measure count value read in step 1 and program it in the
	 * measurement bypass bits (MU_BYP_VAL) of the MMDC PHY Measure Unit
	 * Register for the reduced frequency operation below 100 MHz
	 */
	ldr	r0, [r9, r5]
	ldr	r1, =0x3FF
	bic	r0, r0, r1
	orr	r0, r0, r2
	str	r0, [r9, r5]

	is_mx6qp
	bne	not_6qp_clk_lower_100MHz

	/* Now perform a Force Measurement. */
	ldr	r0, [r9, r5]
	orr	r0, r0, #0x800
	str	r0, [r9, r5]
	/* Wait for FRC_MSR to clear. */
force_measure:
	ldr	r0, [r9, r5]
	and	r0, r0, #0x800
	cmp	r0, #0x0
	bne	force_measure

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	end_clk_lower_100MHz

	ldr	r0, [r8, r5]
	/* Original MU unit count */
	mov	r0, r0, LSR #16
	ldr	r1, =0x3FF
	and	r0, r0, r1
	/* Original MU unit count * 2 */
	mov	r2, r0, LSL #1
	/*
	 * Bypass the automatic measure unit when below 100 MHz
	 * by setting the Measure unit bypass enable bit (MU_BYP_EN)
	 */
	ldr	r0, [r8, r5]
	orr	r0, r0, #0x400
	str	r0, [r8, r5]
	/*
	 * Double the measure count value read in step 1 and program it in the
	 * measurement bypass bits (MU_BYP_VAL) of the MMDC PHY Measure Unit
	 * Register for the reduced frequency operation below 100 MHz
	 */
	ldr	r0, [r8, r5]
	ldr	r1, =0x3FF
	bic	r0, r0, r1
	orr	r0, r0, r2
	str	r0, [r8, r5]
	/* Now perform a Force Measurement. */
	ldr	r0, [r8, r5]
	orr	r0, r0, #0x800
	str	r0, [r8, r5]
	/* Wait for FRC_MSR to clear. */
force_measure_ch1:
	ldr	r0, [r8, r5]
	and	r0, r0, #0x800
	cmp	r0, #0x0
	bne	force_measure_ch1

	b	end_clk_lower_100MHz

not_6qp_clk_lower_100MHz:
	/* For freq lower than 100MHz, need to set RALAT to 2 */
	ldr	r0, [r9, #MX6_MMDC_MDMISC]
	bic	r0, r0, #(0x7 << 6)
	orr	r0, r0, #(0x2 << 6)
	str	r0, [r9, #MX6_MMDC_MDMISC]

end_clk_lower_100MHz:
	.endm

	.macro	mmdc_clk_above_100MHz

	is_mx6qp
	bne	1f
	set_timings_above_100MHz_operation

1:

	/* Make sure that the PHY measurement unit is NOT in bypass mode */
	ldr	r5, =MX6_MMDC_MPMUR0
	ldr	r0, [r9, r5]
	bic	r0, r0, #0x400
	str	r0, [r9, r5]
	/* Now perform a Force Measurement. */
	ldr	r0, [r9, r5]
	orr	r0, r0, #0x800
	str	r0, [r9, r5]
	/* Wait for FRC_MSR to clear. */
force_measure1:
	ldr	r0, [r9, r5]
	and	r0, r0, #0x800
	cmp	r0, #0x0
	bne	force_measure1

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	skip_above_force_measure_ch1

	ldr	r0, [r8, r5]
	bic	r0, r0, #0x400
	str	r0, [r8, r5]
	/* Now perform a Force Measurement. */
	ldr	r0, [r8, r5]
	orr	r0, r0, #0x800
	str	r0, [r8, r5]
	/* Wait for FRC_MSR to clear. */
force_measure1_ch1:
	ldr	r0, [r8, r5]
	and	r0, r0, #0x800
	cmp	r0, #0x0
	bne	force_measure1_ch1

skip_above_force_measure_ch1:
	is_mx6ul_or_sx
	/* For freq lower than 100MHz, need to set RALAT to 5 */
	ldreq	r0, [r9, #MX6_MMDC_MDMISC]
	biceq	r0, r0, #(0x7 << 6)
	orreq	r0, r0, #(0x5 << 6)
	streq	r0, [r9, #MX6_MMDC_MDMISC]

	.endm

/**
 * @brief   Switch the i.MX6 LPDDR2 in self-refresh to
 *          change its clock and exit self-refresh
 *	        IRQs must be disabled.
 *
 * @param[in/out] busfreq_info  busfreq data
 */
	.align	3

func imx6_lpddr2_freq_change , :
UNWIND( .fnstart)
	push	{r1-r12, lr}

	/* Save the input parameters */
	push	{r0}

	ldr		r11, =cpu_mmu_disable_dcache
	mov		lr, pc
	mov		pc, r11

	pop		{r12}

#ifdef CFG_PL310
	/* Disable the L2$ */
	ldr		r0, [r12, #BUSFREQ_INFO_PL310_V_BASE]
	arm_cl2_disable
#endif

bypass_l2_disable:
	tlb_set_to_ocram r12

	/* Keep r8, r9, r10, and r12 as is */
	mov r12, r0
	ldr	r9,  [r12, #BUSFREQ_INFO_MMDC_BASE]
	ldr	r10, [r12, #BUSFREQ_INFO_CCM_BASE]

	/* Ensure TLB preloaded */
	ldr r0, [r10]

	is_mx6ul_or_sx
	moveq	r8, #0
	beq	1f

	/* r8 = MMDC Port 2 if port 2 used, else r8 = 0*/
	/* Check if lpddr2 channel 2 is enabled */
	ldr r8, =MX6_MMDC2_OFFSET
	add r8, r8, r9
	ldr	r0, [r9, #MX6_MMDC_MDMISC]
	ands r0, r0, #(1 << 2)
	moveq r8, #0

1:
	/* Disable Automatic power savings. */
	ldr	r0, [r9, #MX6_MMDC_MAPSR]
	orr	r0, r0, #0x1
	str	r0, [r9, #MX6_MMDC_MAPSR]

	/* MMDC0_MDPDC disable power down timer */
	ldr	r0, [r9, #MX6_MMDC_MDPDC]
	bic	r0, r0, #(0xFF << 8)
	str	r0, [r9, #MX6_MMDC_MDPDC]

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	skip_psd_ch1

	ldr	r0, [r8, #MX6_MMDC_MAPSR]
	orr	r0, r0, #0x1
	str	r0, [r8, #MX6_MMDC_MAPSR]

	ldr	r0, [r8, #MX6_MMDC_MDPDC]
	bic	r0, r0, #(0xFF << 8)
	str	r0, [r8, #MX6_MMDC_MDPDC]

skip_psd_ch1:
	/* delay for a while */
	do_wait #10

	/* Make the DDR explicitly enter self-refresh. */
	enter_dvfs

	/* set SBS step-by-step mode */
	ldr	r0, [r9, #MX6_MMDC_MADPCR0]
	orr	r0, r0, #0x100
	str	r0, [r9, #MX6_MMDC_MADPCR0]

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	skip_sbs_ch1

	enter_dvfs r8

	ldr	r0, [r8, #MX6_MMDC_MADPCR0]
	orr	r0, r0, #0x100
	str	r0, [r8, #MX6_MMDC_MADPCR0]

skip_sbs_ch1:
	ldr r7, [r12, #BUSFREQ_INFO_FREQ]
	ldr	r1, =FREQ_100MHZ
	cmp	r7, r1
	bgt	set_ddr_mu_above_100

	is_mx6ul_or_sx
	bne	do_clk_lower_100MHz

	/* Check if the DLL is off */
	ldr	r0, [r12, #BUSFREQ_INFO_DLL_OFF]
	cmp	r0, #1
	beq	set_ddr_mu_above_100

do_clk_lower_100MHz:
	mmdc_clk_lower_100MHz

set_ddr_mu_above_100:
	ldr	r1, =FREQ_24MHZ
	cmp	r7, r1
	beq	set_to_24MHz

	ldr	r1, =FREQ_100MHZ
	cmp	r7, r1
	beq set_to_100MHz

	ldr r1, =FREQ_400MHZ
	cmp r7, r1
	switch_to_400MHz
	b	done

set_to_24MHz:
	switch_to_24MHz
	b	done

set_to_100MHz:
	switch_to_100MHz

done:
	ldr	r1,=FREQ_100MHZ
	cmp	r7, r1
	blt	skip_mmdc_clk_check
	mmdc_clk_above_100MHz

skip_mmdc_clk_check:

	/* clear DVFS - exit from self refresh mode */
	exit_dvfs

	/* Enable Automatic power savings. */
	ldr	r0, [r9, #MX6_MMDC_MAPSR]
	bic	r0, r0, #0x1
	str	r0, [r9, #MX6_MMDC_MAPSR]

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	skip_enable_psd_ch1

	/* clear DVFS - exit self refresh mode. */
	exit_dvfs r8

	ldr	r0, [r8, #MX6_MMDC_MAPSR]
	bic	r0, r0, #0x1
	str	r0, [r8, #MX6_MMDC_MAPSR]

skip_enable_psd_ch1:
	ldr	r1, =FREQ_24MHZ
	cmp	r7, r1
	beq	skip_power_down

	/* Enable MMDC power down timer. */
	ldr	r0, [r9, #MX6_MMDC_MDPDC]
	orr	r0, r0, #0x5500
	str	r0, [r9, #MX6_MMDC_MDPDC]

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	skip_power_down

	ldr	r0, [r8, #MX6_MMDC_MDPDC]
	orr	r0, r0, #0x5500
	str	r0, [r8, #MX6_MMDC_MDPDC]

skip_power_down:
	/* clear SBS - unblock DDR accesses */
	ldr	r0, [r9, #MX6_MMDC_MADPCR0]
	bic	r0, r0, #0x100
	str	r0, [r9, #MX6_MMDC_MADPCR0]

	/* Check if lpddr2 channel 2 is enabled */
	cmp r8, #0
	beq	skip_disable_sbs_ch1

	ldr	r0, [r8, #MX6_MMDC_MADPCR0]
	bic	r0, r0, #0x100
	str	r0, [r8, #MX6_MMDC_MADPCR0]

skip_disable_sbs_ch1:
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

	tlb_back_to_ddr r12

#ifdef CFG_PL310
	/* Enable the L2$ */
	ldr		r0, [r12, #BUSFREQ_INFO_PL310_V_BASE]
	ldr		r11, =arm_cl2_enable
	mov		lr, pc
	mov		pc, r11
#endif

bypass_l2_enable:
    /* Enable D$ */
    read_sctlr  r2
    orr     r2, r2, #SCTLR_C
    write_sctlr r2
	isb

	pop	{r1-r12, lr}

	/* Restore registers */
	mov	pc, lr

	/* Ensure that all constant will be stored here */
	.ltorg

	.equ	FREQ_400MHZ, 400000000
	.equ	FREQ_100MHZ, 100000000
	.equ	FREQ_24MHZ,   24000000

UNWIND( .fnend)
END_FUNC imx6_lpddr2_freq_change


FUNC get_imx6_lpddr2_freq_change_size , :
UNWIND( .fnstart)
	subs	r0, pc, #8
	ldr		r1, =imx6_lpddr2_freq_change
	sub		r0, r0, r1
	bx		lr
UNWIND( .fnend)
END_FUNC get_imx6_lpddr2_freq_change_size

