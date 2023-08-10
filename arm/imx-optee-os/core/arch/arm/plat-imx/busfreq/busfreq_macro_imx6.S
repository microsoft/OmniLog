/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_macro_imx6.S
 *
 * @brief   Implementation of the bus frequency common macro
 *          on i.MX6 devices
 */

/* Registers includes */
#include <imx-regs.h>
#include <kernel/tz_ssvce_def.h>

#ifdef CFG_PL310
	.macro arm_cl2_disable
loop_dis_sync:
	ldr	r1, [r0, #PL310_SYNC]
	cmp	r1, #0
	bne	loop_dis_sync

	mov	r1, #1
	str	r1, [r0, #PL310_SYNC]
wait_dis_sync:
	ldr	r1, [r0, #PL310_SYNC]
	cmp	r1, #0
	bne	wait_dis_sync

	/* disable PL310 ctrl -> only set lsb bit */
	mov	r1, #0x0
	str	r1, [r0, #PL310_CTRL]

	dsb
	isb
	.endm
#endif

.extern iram_tlb_phys_addr

	.macro tlb_set_to_ocram base
	/* save ttbr */
	read_ttbr1 r7
	str	r7, [\base, #BUSFREQ_INFO_TTBR1_OFF]

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
	bic	r6, r6, #SCTLR_Z
	write_sctlr r6

	dsb
	isb

	/* Store the IRAM table in TTBR1/TTBR0 */
	write_ttbr1 r7

	/* Read TTBCR and set PD0=1 and PD1=0 */
	/* Warning: unknown behaviour if LPAE is enabled */
	read_ttbcr r6
	bic	r6, r6, #(TTBCR_PD1 | TTBCR_PD0)
	orr	r6, r6, #TTBCR_PD0
	write_ttbcr r6

	dsb
	isb

	/* flush the TLB */
	write_tlbiallis
	isb
	write_tlbiall
	isb
	.endm

	.macro tlb_back_to_ddr base
	/* Restore the TTBCR */
	dsb
	isb

	/* Read TTBCR and set PD0=0 and PD1=0 */
	read_ttbcr r6
	bic	r6, r6, #(TTBCR_PD1 | TTBCR_PD0)
	write_ttbcr r6

	dsb
	isb

	/* flush the TLB */
	write_tlbiallis

	dsb
	isb

	/* Enable Branch Prediction, Z bit in SCTLR. */
	read_sctlr r6
	orr	r6, r6, #SCTLR_Z
	write_sctlr r6

	/* Flush the Branch Target Address Cache (BTAC) */
	write_bpiallis

	/* restore ttbr */
	ldr	r6, [\base, #BUSFREQ_INFO_TTBR1_OFF]
	write_ttbr1 r6

	isb
	.endm


	.macro is_mx6qp
	ldr	r0, [r12, #BUSFREQ_INFO_CPU_TYPE]
	ldr	r1, =BUSFREQ_CPU_MX6QP
	cmp	r0, r1
	.endm

	.macro is_mx6ul_or_sx
	ldr	r0, [r12, #BUSFREQ_INFO_CPU_TYPE]
	ldr	r1, =BUSFREQ_CPU_MX6UL
	cmp	r0, r1
	ldrne	r1, =BUSFREQ_CPU_MX6SX
	cmpne	r0, r1
	.endm

	.macro do_wait delay
	mov	r1, \delay
1:
	mov	r2, #MX6_MMDC_MDCTL
2:
	ldr	r0, [r9, r2]
	add	r2, r2, #4
	cmp	r2, #16
	bne	2b
	sub	r1, r1, #1
	cmp	r1, #0
	bgt	1b
	.endm

	.macro con_req_ack_set
	mov	r0, #(1 << 15)
	str	r0, [r9, #MX6_MMDC_MDSCR]
1:
	ldr	r0, [r9, #MX6_MMDC_MDSCR]
	ands	r0, r0, #(1 << 14)
	beq	1b
	.endm

	.macro con_req_ack_clr
	mov	r0, #0
	str	r0, [r9, #MX6_MMDC_MDSCR]
1:
	ldr	r0, [r9, #MX6_MMDC_MDSCR]
	ands	r0, r0, #(1 << 14)
	bne	1b
	.endm

	.macro dvfs_ack_set base=r9
1:
	ldr	r0, [\base, #MX6_MMDC_MAPSR]
	ands	r0, r0, #(1 << 25)
	beq	1b
	.endm

	.macro dvfs_ack_clr base=r9
1:
	ldr	r0, [\base, #MX6_MMDC_MAPSR]
	ands	r0, r0, #(1 << 25)
	bne	1b
	.endm

	.macro enter_dvfs base=r9
	ldr	r0, [\base, #MX6_MMDC_MAPSR]
	orr	r0, r0, #(1 << 21)
	str	r0, [\base, #MX6_MMDC_MAPSR]

	dvfs_ack_set \base
	.endm

	.macro exit_dvfs base=r9
	ldr	r0, [\base, #MX6_MMDC_MAPSR]
	bic	r0, r0, #(1 << 21)
	str	r0, [\base, #MX6_MMDC_MAPSR]

	dvfs_ack_clr \base
	.endm

	.macro wait_ccm_handshake
100:
	ldr	r0, [r10, #CCM_CDHIPR]
	cmp	r0, #0
	bne	100b
	.endm

	.macro	switch_to_528MHz

	/* check if periph_clk_sel is already set */
	ldr	r0, [r10, #CCM_CBCDR]
	and	r0, r0, #(1 << 25)
	cmp	r0, #(1 << 25)
	beq	set_ahb_podf_before_switch_528

	/* change periph_clk to be sourced from pll3_clk. */
	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(3 << 12)
	str	r0, [r10, #CCM_CBCMR]

	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x38 << 20)
	str	r0, [r10, #CCM_CBCDR]

	/*
	 * set the AHB dividers before the switch,
	 * don't change AXI clock divider,
	 * set the MMDC_DIV=1, AXI_DIV = 2, AHB_DIV=4,
	 */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r2, =0x3f1f00
	bic	r0, r0, r2
	orr	r0, r0, #0xd00
	orr	r0, r0, #(1 << 16)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/* now switch periph_clk to pll3_main_clk. */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	b	switch_pre_periph_clk_528

set_ahb_podf_before_switch_528:
	/*
	 * set the MMDC_DIV=1, AXI_DIV = 2, AHB_DIV=4,
	 */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r2, =0x3f1f00
	bic	r0, r0, r2
	orr	r0, r0, #0xd00
	orr	r0, r0, #(1 << 16)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

switch_pre_periph_clk_528:

	/* now switch pre_periph_clk to PLL2_528MHz. */
	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(0xC << 16)
	str	r0, [r10, #CCM_CBCMR]

	/* now switch periph_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	.endm

	.macro	switch_to_400Mz_UL_SX
	/* check whether periph2_clk is already from top path */
	ldr	r0, [r10, #CCM_CBCDR]
	ands	r0, #(1 << 26)
	beq	skip_periph2_clk2_switch_400_UL_SX

	/* now switch periph2_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 26)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/*
	 * on i.MX6SX, pre_periph2_clk will be always from
	 * pll2_pfd2, so no need to set pre_periph2_clk
	 * parent, just set the mmdc divider directly.
	 */
skip_periph2_clk2_switch_400_UL_SX:

	/* fabric_mmdc_podf to 0 */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x7 << 3)
	str	r0, [r10, #CCM_CBCDR]

	.endm

	.macro	switch_to_400MHz

	is_mx6qp
	beq	switch_to_400MHz_6QP

	switch_to_400Mz_UL_SX
	b	switch_to_400Mz_exit

switch_to_400MHz_6QP:
	/* check if periph_clk_sel is already set. */
	ldr	r0, [r10, #CCM_CBCDR]
	and	r0, r0, #(1 << 25)
	cmp	r0, #(1 << 25)
	beq	set_ahb_podf_before_switch1

	/* change periph_clk to be sourced from pll3_clk. */
	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(3 << 12)
	str	r0, [r10, #CCM_CBCMR]

	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x38 << 24)
	str	r0, [r10, #CCM_CBCDR]

	/* now switch periph_clk to pll3_main_clk. */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	b	switch_pre_periph_clk_400

set_ahb_podf_before_switch1:
	/*
	 * set the MMDC_DIV=1, AXI_DIV = 2, AHB_DIV=4,
	 */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r2, =0x3f1f00
	bic	r0, r0, r2
	orr	r0, r0, #(0x9 << 8)
	orr	r0, r0, #(1 << 16)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

switch_pre_periph_clk_400:

	/* now switch pre_periph_clk to PFD_400MHz. */
	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(0xc << 16)
	orr	r0, r0, #(0x4 << 16)
	str	r0, [r10, #CCM_CBCMR]

	/* now switch periph_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/*
	 * change AHB divider so that we are at 400/3=133MHz.
	 * don't change AXI clock divider.
	 * set the MMDC_DIV=1, AXI_DIV=2, AHB_DIV=3,
	 */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r2, =0x3f1f00
	bic	r0, r0, r2
	orr	r0, r0, #(0x9 << 8)
	orr	r0, r0, #(1 << 16)
	str	r0, [r10, #CCM_CBCDR]

switch_to_400Mz_exit:
	wait_ccm_handshake

	.endm

	.macro	switch_to_100MHz_UL_SX
	/* check whether periph2_clk is from top path */
	ldr	r0, [r10, #CCM_CBCDR]
	ands	r0, #(1 << 26)
	beq	skip_periph2_clk2_switch_100_UL_SX

	/* now switch periph2_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 26)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/*
	 * on i.MX6SX, pre_periph2_clk will be always from
	 * pll2_pfd2, so no need to set pre_periph2_clk
	 * parent, just set the mmdc divider directly.
	 */
skip_periph2_clk2_switch_100_UL_SX:

	/* fabric_mmdc_podf to 3 so that mmdc is 400 / 4 = 100MHz */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x7 << 3)
	orr	r0, r0, #(0x3 << 3)
	str	r0, [r10, #CCM_CBCDR]

	.endm

	.macro	switch_to_100MHz

	is_mx6qp
	beq	switch_to_100MHz_6QP

	switch_to_100MHz_UL_SX
	b	switch_to_100MHz_exit

switch_to_100MHz_6QP:
	/* check if periph_clk_sel is already set. */
	ldr	r0, [r10, #CCM_CBCDR]
	and	r0, r0, #(1 << 25)
	cmp	r0, #(1 << 25)
	beq	switch_pre_periph_clk_100
	/*
	 * set the periph_clk to be sourced from PLL2_PFD_200M
	 * change periph_clk to be sourced from pll3_clk.
	 * ensure PLL3 is the source and set the divider to 1.
	 */
	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(0x3 << 12)
	str	r0, [r10, #CCM_CBCMR]

	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x38 << 24)
	str	r0, [r10, #CCM_CBCDR]

	/* now switch periph_clk to pll3_main_clk. */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

switch_pre_periph_clk_100:
	/* now switch pre_periph_clk to PFD_200MHz. */
	ldr	r0, [r10, #CCM_CBCMR]
	orr	r0, r0, #(0xc << 16)
	str	r0, [r10, #CCM_CBCMR]

	/* set the MMDC_DIV=2, AXI_DIV=4, AHB_DIV=8 */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r1, =0x3f1f00
	bic	r0, r0, r1
	orr	r0, r0, #(0x8 << 16)
	orr	r0, r0, #(0x3 << 16)

	/*
	 * if changing AHB divider remember to change
	 * the IPGPER divider too below.
	 */
	orr	r0, r0, #0x1d00
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/* now switch periph_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

switch_to_100MHz_exit:
	wait_ccm_handshake

	.endm

	.macro	switch_to_50MHz_UL_SX

	/* check whether periph2_clk is already from top path */
	ldr	r0, [r10, #CCM_CBCDR]
	ands	r0, #(1 << 26)
	beq	skip_periph2_clk2_switch_50_UL_SX

	/* now switch periph2_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 26)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/*
	 * pre_periph2_clk will be always from
	 * pll2_pfd2, so no need to set pre_periph2_clk
	 * parent, just set the mmdc divider directly.
	 */
skip_periph2_clk2_switch_50_UL_SX:

	/* fabric_mmdc_podf to 7 so that mmdc is 400 / 8 = 50MHz */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(0x7 << 3)
	str	r0, [r10, #CCM_CBCDR]

	.endm

	.macro	switch_to_50MHz

	is_mx6qp
	beq	switch_to_50MHz_6QP

	switch_to_50MHz_UL_SX
	b	switch_to_50MHz_exit

switch_to_50MHz_6QP:
	/* check if periph_clk_sel is already set. */
	ldr	r0, [r10, #CCM_CBCDR]
	and	r0, r0, #(1 << 25)
	cmp	r0, #(1 << 25)
	beq	switch_pre_periph_clk_50

	/*
	 * set the periph_clk to be sourced from PLL2_PFD_200M
	 * change periph_clk to be sourced from pll3_clk.
	 * ensure PLL3 is the source and set the divider to 1.
	 */
	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(0x3 << 12)
	str	r0, [r10, #CCM_CBCMR]

	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x38 << 24)
	str	r0, [r10, #CCM_CBCDR]

	/* now switch periph_clk to pll3_main_clk. */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

switch_pre_periph_clk_50:

	/* now switch pre_periph_clk to PFD_200MHz. */
	ldr	r0, [r10, #CCM_CBCMR]
	orr	r0, r0, #(0xc << 16)
	str	r0, [r10, #CCM_CBCMR]

	/*
	 * set the MMDC_DIV=4, AXI_DIV = 4, AHB_DIV=8,
	 */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r2, =0x3f1f00
	bic	r0, r0, r2
	orr	r0, r0, #(0x18 << 16)
	orr	r0, r0, #(0x3 << 16)

	/*
	 * if changing AHB divider remember to change
	 * the IPGPER divider too below.
	 */
	orr	r0, r0, #0x1d00
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/* now switch periph_clk back. */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

switch_to_50MHz_exit:
	wait_ccm_handshake

	.endm

	.macro	switch_to_24MHz_UL_SX
	/* Set periph_clk2_sel to OSC_CLK */
	ldr	r0, [r10, #CCM_CBCMR]
	orr	r0, r0, #(1 << 20)
	str	r0, [r10, #CCM_CBCMR]

	/* Set periph2_clk2_podf to 0 */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #0x7
	str	r0, [r10, #CCM_CBCDR]

	/* Set periph2_clk sel to periph2_clk2 */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(0x1 << 26)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/* Set fabric_mmdc_podf to 0 */
	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x7 << 3)
	str	r0, [r10, #CCM_CBCDR]

	.endm

	.macro	switch_to_24MHz

	is_mx6qp
	beq switch_to_24MHz_6QP

	switch_to_24MHz_UL_SX
	b	switch_to_24MHz_exit

switch_to_24MHz_6QP:
	/*
	 * change the freq now try setting DDR to 24MHz.
	 * source it from the periph_clk2 ensure the
	 * periph_clk2 is sourced from 24MHz and the
	 * divider is 1.
	 */

	ldr	r0, [r10, #CCM_CBCMR]
	bic	r0, r0, #(0x3 << 12)
	orr	r0, r0, #(1 << 12)
	str	r0, [r10, #CCM_CBCMR]

	ldr	r0, [r10, #CCM_CBCDR]
	bic	r0, r0, #(0x38 << 24)
	str	r0, [r10, #CCM_CBCDR]

	/* now switch periph_clk to 24MHz. */
	ldr	r0, [r10, #CCM_CBCDR]
	orr	r0, r0, #(1 << 25)
	str	r0, [r10, #CCM_CBCDR]

	wait_ccm_handshake

	/* change all the dividers to 1. */
	ldr	r0, [r10, #CCM_CBCDR]
	ldr	r2, =0x3f1f00
	bic	r0, r0, r2
	orr	r0, r0, #(1 << 8)
	str	r0, [r10, #CCM_CBCDR]

switch_to_24MHz_exit:
	wait_ccm_handshake
	.endm


