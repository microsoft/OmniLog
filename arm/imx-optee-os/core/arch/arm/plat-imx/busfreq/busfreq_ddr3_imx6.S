/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_ddr3_imx6.S
 *
 * @brief   Implementation of the bus frequency DDR3
 *          assembly function on i.MX6 devices
 */
/* Global includes */
#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/unwind.h>

/* Generated file */
#include <generated/busfreq_imx6_defines.h>

/* Local includes */
#include "busfreq_imx6.h"

#include "busfreq_macro_imx6.S"

	.align	3
/**
 * @brief   Switch the i.MX6 DDR3 in self-refresh to
 *          change its clock and exit self-refresh
 *	        IRQs must be disabled.
 *
 * @param[in/out] busfreq_info  busfreq data
 */

FUNC imx6_ddr3_freq_change, :
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

	/* Keep r9, r10, r11 and r12 as is */
	ldr	r9,  [r12, #BUSFREQ_INFO_MMDC_BASE]
	ldr	r10, [r12, #BUSFREQ_INFO_CCM_BASE]
	ldr	r11, [r12, #BUSFREQ_INFO_IOMUX_BASE]

	/* Make sure TLB preloaded */
	ldr r0, [r10]
	ldr r0, [r11]

	is_mx6ul_or_sx
	moveq	r8, #0
	beq	1f

	/* r8 = MMDC Port 2 */
	ldr r8, =MX6_MMDC2_OFFSET
	add r8, r8, r9

1:
	/* Read the Original MU delay value */
	/* Value must be read before doing any MMDC configuration changes */
	ldr	r0, [r9, #MX6_MMDC_MPMUR0]
	mov	r7, r0, lsr #BP_MX6_MMDC_MPMUR0_MU_UNIT_DEL_NUM
	ldr	r0, =0x3FF
	and	r7, r7, r0

	/* disable automatic power saving. */
	ldr	r0, [r9, #MX6_MMDC_MAPSR]
	orr	r0, r0, #0x1
	str	r0, [r9, #MX6_MMDC_MAPSR]

	/* disable MMDC power down timer. */
	ldr	r0, [r9, #MX6_MMDC_MDPDC]
	bic	r0, r0, #(0xFF << 8)
	str	r0, [r9, #MX6_MMDC_MDPDC]

	do_wait #4

	/* set CON_REG */
	con_req_ack_set

	/* Load the requested frequency */
	ldr r4, [r12, #BUSFREQ_INFO_FREQ]

	/* Check if we are on imx6ul or 6sx */
	is_mx6ul_or_sx
	beq	2f

	/*
	 * if requested frequency is great than
	 * 300MHz, skip setting bypass adopt mode.
	 */
	ldr r0, =FREQ_300MHZ
	cmp	r4, r0
	bge	1f

	is_mx6qp
	bne	1f
	/* Switch to adopt mode, set MMDC0_MAARCR bit25~26 to 2b'01 */
	ldr	r0, [r9, #MX6_MMDC_MAARCR]
	bic	r0, r0, #(0x3 << 25)
	orr	r0, r0, #(0x1 << 25)
	str	r0, [r9, #MX6_MMDC_MAARCR]
1:
	ldr	r0, =0x00008050
	str	r0, [r9, #MX6_MMDC_MDSCR]
	ldr	r0, =0x00008058
	str	r0, [r9, #MX6_MMDC_MDSCR]

2:
	/*
	 * if requested frequency is greater than
	 * 300MHz go to DLL on mode.
	 */
	ldr	r0, =FREQ_300MHZ
	cmp	r4, r0
	bge	dll_on_mode

dll_off_mode:
	ldr r0, [r12, #BUSFREQ_INFO_DLL_OFF]
	/* if DLL is currently on, turn it off. */
	cmp	r0, #1
	beq	continue_dll_off_1

	ldr	r0, =0x00018031
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, =0x00018039
	str	r0, [r9, #MX6_MMDC_MDSCR]

	do_wait #10

continue_dll_off_1:
	/* set DVFS - enter self refresh mode */
	ldr	r0, [r9, #MX6_MMDC_MAPSR]
	orr	r0, r0, #(1 << 21)
	str	r0, [r9, #MX6_MMDC_MAPSR]

	/* de-assert con_req */
	mov	r0, #0x0
	str	r0, [r9, #MX6_MMDC_MDSCR]

	dvfs_ack_set

	ldr	r0, =FREQ_24MHZ
	cmp	r4, r0
	beq	switch_freq_24

	switch_to_50MHz
	b	continue_dll_off_2

switch_freq_24:
	switch_to_24MHz

continue_dll_off_2:
	/* set SBS - block ddr accesses */
	ldr	r0, [r9, #MX6_MMDC_MADPCR0]
	orr	r0, r0, #(1 << 8)
	str	r0, [r9, #MX6_MMDC_MADPCR0]

	/* clear DVFS - exit from self refresh mode */
	exit_dvfs

	/* if DLL was previously on, continue DLL off routine. */
	ldr r0, [r12, #BUSFREQ_INFO_DLL_OFF]
	cmp r0, #1
	beq continue_dll_off_3

	is_mx6ul_or_sx
	ldr	r0, =0x00018031
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, =0x00018039
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldreq	r0, =0x04208030
	ldrne	r0, =0x08208030
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldreq	r0, =0x04208038
	ldrne	r0, =0x08208038
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, =0x00088032
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, =0x0008803A
	str	r0, [r9, #MX6_MMDC_MDSCR]

	/* delay for a while. */
	do_wait #4

	ldr	r0, [r9, #MX6_MMDC_MDCFG0]
	bic	r0, r0, #0xf
	orr	r0, r0, #0x3
	str	r0, [r9, #MX6_MMDC_MDCFG0]

	ldr	r0, [r9, #MX6_MMDC_MDCFG1]
	bic	r0, r0, #0x7
	orr	r0, r0, #0x4
	str	r0, [r9, #MX6_MMDC_MDCFG1]

	ldr	r0, [r9, #MX6_MMDC_MDMISC]
	bic	r0, r0, #(0x3 << 16) // set walat = 0x1
	orr r0, r0, #(0x1 << 16)
	bic	r0, r0, #(0x7 << 6)  // set ralat = 0x2
	orr r0, r0, #(0x2 << 6)
	str	r0, [r9, #MX6_MMDC_MDMISC]

	/* enable dqs pull down in the IOMUX. */
	ldr r1, [r12, #BUSFREQ_INFO_IOMUX_OFFSETS]
	ldr r4, [r12, #BUSFREQ_INFO_IOMUX_OFFSETS_SIZE]
	ldr	r2, =0x3028
update_iomux:
	ldr	r0, [r1], #8
	ldr	r3, [r11, r0]
	orr r3, r3, r2
	str	r3, [r11, r0]
	sub	r4, r4, #1
	cmp	r4, #0
	bgt	update_iomux

	/*	ODT disabled. */
	mov	r0, #0
	ldr	r1, =MX6_MMDC_MPODTCTRL
	str	r0, [r9, r1]
	/* is channel 2 */
	cmp r8, #0
	strne	r0, [r8, r1]

	/* DQS gating disabled. */
	ldr	r1, =MX6_MMDC_MPDGCTRL0
	ldr	r0, [r9, r1]
	orr	r0, r0, #(1 << 29)
	str	r0, [r9, r1]

	/* is channel 2 */
	ldrne	r0, [r8, r1]
	orrne	r0, r0, #(0x1 << 29)
	strne	r0, [r8, r1]

	/* Add workaround for ERR005778.*/
	/* double the original MU_UNIT_DEL_NUM. */
	lsl	r7, r7, #1

	/* Bypass the automatic MU by setting the mu_byp_en */
	ldr r1, =MX6_MMDC_MPMUR0
	ldr	r0, [r9, r1]
	orr	r0, r0, #0x400
	orr	r0, r0, r7
	str	r0, [r9, r1]
	/* is channel 2 */
	strne	r0, [r8, r1]

	/* Now perform a force measure */
	ldr	r0, [r9, r1]
	orr	r0, r0, #0x800
	str	r0, [r9, r1]
	/* is channel 2 */
	strne	r0, [r8, r1]

	/* Wait for FRC_MSR to clear. */
1:
	ldr	r0, [r9, r1]
	and	r0, r0, #0x800
	/* is channel 2 */
	cmp r8, #0
	ldrne	r3, [r8, r1]
	andne	r3, r3, #0x800
	orrne	r0, r0, r3
	cmp	r0, #0x0
	bne	1b

continue_dll_off_3:
	/* clear SBS - unblock accesses to DDR. */
	ldr	r0, [r9, #MX6_MMDC_MADPCR0]
	bic	r0, r0, #(0x1 << 8)
	str	r0, [r9, #MX6_MMDC_MADPCR0]

	con_req_ack_clr

	b	done

dll_on_mode:
	/* assert DVFS - enter self refresh mode. */
	ldr	r0, [r9, #MX6_MMDC_MAPSR]
	orr	r0, r0, #(1 << 21)
	str	r0, [r9, #MX6_MMDC_MAPSR]

	/* de-assert CON_REQ. */
	mov	r0, #0x0
	str	r0, [r9, #MX6_MMDC_MDSCR]

	/* poll DVFS ack. */
	dvfs_ack_set

	/* Load the requested frequency */
	ldr r4, [r12, #BUSFREQ_INFO_FREQ]
	ldr	r1, =FREQ_528MHZ
	cmp	r4, r1
	beq	switch_freq_528

	switch_to_400MHz

	b	continue_dll_on

switch_freq_528:
	switch_to_528MHz

continue_dll_on:

	/* set SBS step-by-step mode. */
	ldr	r0, [r9, #MX6_MMDC_MADPCR0]
	orr	r0, r0, #(1 << 8)
	str	r0, [r9, #MX6_MMDC_MADPCR0]

	/* clear DVFS - exit self refresh mode. */
	exit_dvfs

	/* if DLL is currently off, turn it back on. */
	ldr r0, [r12, #BUSFREQ_INFO_DLL_OFF]
	cmp	r0, #0
	beq	update_calibration_only

	ldr r1, =MX6_MMDC_MPZQHWCTRL
	ldr	r0, [r9, r1]
	orr	r0, r0, #0x3
	str	r0, [r9, r1]
	/* is channel 2 */
	cmp	r8, #0
	strne	r0, [r8, r1]

	/* enable DQS gating. */
	ldr	r1, =MX6_MMDC_MPDGCTRL0
	ldr	r0, [r9, r1]
	bic	r0, r0, #(1 << 29)
	str	r0, [r9, r1]

	/* is channel 2 */
	ldrne	r0, [r8, r1]
	bicne	r0, r0, #(1 << 29)
	strne	r0, [r8, r1]

	/* force measure. */
	mov	r0, #0x800
	ldr r1, =MX6_MMDC_MPMUR0
	str	r0, [r9, r1]
	/* is channel 2 */
	strne	r0, [r8, r1]

	/* Wait for FRC_MSR to clear. */
1:
	ldr	r0, [r9, r1]
	and	r0, r0, #0x800
	/* is channel 2 */
	cmp	r8, #0
	ldrne	r3, [r8, r1]
	andne	r3, r3, #0x800
	orrne	r0, r0, r3
	cmp	r0, #0x0
	bne	1b

	/* disable dqs pull down in the IOMUX. */
	ldr r1, [r12, #BUSFREQ_INFO_IOMUX_OFFSETS]
	ldr r3, [r12, #BUSFREQ_INFO_IOMUX_OFFSETS_SIZE]
update_iomux1:
	ldr	r0, [r1], #0x4
	ldr	r2, [r1], #0x4
	str	r2, [r11, r0]
	sub	r3, r3, #1
	cmp	r3, #0
	bgt	update_iomux1

	/* config MMDC timings to High MHz. */
	ldr r3, [r12, #BUSFREQ_INFO_DDR_SETTINGS]
	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	is_mx6ul_or_sx
	/* configure ddr devices to dll on, odt. */
	ldreq r0, =0x00028031
	ldrne r0, =0x00048031
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldreq r0, =0x00028039
	ldrne r0, =0x00048039
	str	r0, [r9, #MX6_MMDC_MDSCR]

	/* delay for while. */
	do_wait #4

	/* reset dll. */
	is_mx6ul_or_sx
	ldreq r0, =0x09208030
	ldrne r0, =0x09408030
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldreq r0, =0x09208038
	ldrne r0, =0x09408038
	str	r0, [r9, #MX6_MMDC_MDSCR]

	/* delay for while. */
	do_wait #100

	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	ldr	r0, =0x00428031
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, =0x00428039
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	ldr	r0, [r3], #0x4
	ldr	r1, [r3], #0x4
	str	r1, [r9, r0]

	/* issue a zq command. */
	ldr	r0, =0x04008040
	str	r0, [r9, #MX6_MMDC_MDSCR]

	ldr	r0, =0x04008048
	str	r0, [r9, #MX6_MMDC_MDSCR]

	/* MMDC ODT enable. */
	ldr	r0, [r3], #0x4
	ldr	r1, [r3]
	str	r1, [r9, r0]

	/* is channel 2 */
	cmp	r8, #0
	ldrne	r2, =MX6_MMDC_MPODTCTRL
	strne	r1, [r8, r2]

	/* delay for while. */
	do_wait #40

	/* enable MMDC power down timer. */
	ldr	r0, [r9, #MX6_MMDC_MDPDC]
	orr	r0, r0, #(0x55 << 8)
	str	r0, [r9, #MX6_MMDC_MDPDC]

update_calibration_only:
	/* write the new calibration values. */
	ldr r3, [r12, #BUSFREQ_INFO_DDR_CALIBRATION]
	ldr r1, [r12, #BUSFREQ_INFO_DDR_CALIBRATION_SIZE]

update_calib:
	ldr	r0, [r3], #0x4
	ldr	r2, [r3], #0x4
	str	r2, [r9, r0]
	sub	r1, r1, #1
	cmp	r1, #0
	bgt	update_calib

	/* perform a force measurement. */
	mov r0, #0x800
	ldr r1, =MX6_MMDC_MPMUR0
	str	r0, [r9, r1]
	/* is channel 2 */
	cmp	r8, #0
	strne	r0, [r8, r1]

	/* Wait for FRC_MSR to clear. */
1:
	ldr	r0, [r9, r1]
	and	r0, r0, #0x800
	/* is channel 2 */
	cmp	r8, #0
	ldrne	r3, [r8, r1]
	andne	r3, r3, #0x800
	orrne	r0, r0, r3
	cmp	r0, #0x0
	bne	1b

force_measurement_both_channels_done:
	/* clear SBS - unblock DDR accesses. */
	ldr	r0, [r9, #MX6_MMDC_MADPCR0]
	bic	r0, r0, #(1 << 8)
	str	r0, [r9, #MX6_MMDC_MADPCR0]

	is_mx6qp
	bne	3f
	/*
	 * Switch back to adopt_bp mode, set MMDC0_MAARCR
	 * bit25~26 to 2b'10.
	 */
	ldr	r0, [r9, #MX6_MMDC_MAARCR]
	bic	r0, r0, #(0x3 << 25)
	orr	r0, r0, #(0x2 << 25)
	str	r0, [r9, #MX6_MMDC_MAARCR]
3:
	con_req_ack_clr

done:
	/* MMDC0_MAPSR adopt power down enable. */
	ldr	r0, [r9, #MX6_MMDC_MAPSR]
	bic	r0, r0, #0x1
	str	r0, [r9, #MX6_MMDC_MAPSR]

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

	/* restore registers */
	pop		{r1-r12, lr}
	mov	pc, lr

	/* Ensure that all constant will be stored here */
	.ltorg

	.equ	FREQ_528MHZ, 528000000
	.equ	FREQ_300MHZ, 300000000
	.equ	FREQ_24MHZ,   24000000

UNWIND( .fnend)
END_FUNC imx6_ddr3_freq_change

FUNC get_imx6_ddr3_freq_change_size , :
UNWIND( .fnstart)
	subs	r0, pc, #8
	ldr		r1, =imx6_ddr3_freq_change
	sub		r0, r0, r1
	bx		lr
UNWIND( .fnend)
END_FUNC get_imx6_ddr3_freq_change_size
