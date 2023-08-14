/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq_asm_imx7.S
 *
 * @brief   Implementation of the bus frequency
 *          assembly function on i.MX7 devices
 */
/* Global includes */
#include <arm.h>
#include <arm32_macros.S>
#include <asm.S>
#include <kernel/unwind.h>

#include <imx-regs.h>
/* Generated file */
#include <generated/busfreq_imx7_defines.h>

#define MX7_IOMUX_GPR8	IOMUX_GPRx_OFFSET(8)

#define CCM_TARGET_ROOT49  CCM_TARGET_ROOTx(49)
#define CCM_TARGET_ROOT65  CCM_TARGET_ROOTx(65)

#define REV_1_1		0x11

	.macro switch_to_533mhz_ddr3_start

	mov	r0, #0x2
	str	r0, [r9, #MX7_DDRC_DBG1]

	mov	r0, #0x78
	str	r0, [r11, #MX7_IOMUX_GPR8]
	orr	r0, r0, #0x100
	str	r0, [r11, #MX7_IOMUX_GPR8]

	mov	r1, #(0x3 << 28)
1:
	ldr	r0, [r9, #MX7_DDRC_DBGCAM]
	and	r0, r0, r1
	cmp	r0, r1
	bne	1b

	mov	r1, #0x1
2:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	2b

	ldr	r0, =0x10f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	mov	r0, #0x1
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800010f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r0, #0x20
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	mov	r1, #0x23
3:
	ldr	r0, [r9, #MX7_DDRC_STAT]
	and	r0, r0, r1
	cmp	r0, r1
	bne	3b

	ldr	r0, =0x03040001
	str	r0, [r9, #MX7_DDRC_MSTR]

	ldr	r0, =0x40800020
	str	r0, [r9, #MX7_DDRC_ZQCTL0]

	ldr	r0, =0x10210100
	str	r0, [r8, #MX7_DDRPHY_PHY_CON1]

	ldr	r0, =0x00040046
	str	r0, [r9, #MX7_DDRC_RFSHTMG]
	.endm

	.macro switch_to_533mhz_ddr3_end
	cmp	r7, #REV_1_1
	bne	4f

	ldr	r0, =0x40404040
	str	r0, [r8, #MX7_DDRPHY_CA_WLDSKEW_CON0]
	ldr	r0, =0x18181818
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	ldr	r0, =0x40401818
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]
	b	5f
4:
	mov	r0, #0x0
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]
5:
	ldr	r0, =0x11000008
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]
	ldr	r0, =0x10000008
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]

	mov	r1, #0x4
6:
	ldr	r0, [r8, #MX7_DDRPHY_MDLL_CON1]
	and	r0, r0, r1
	cmp	r0, r1
	bne	6b

	mov	r0, #0x1
	str	r0, [r9, #MX7_DDRC_RFSHCTL3]
	mov	r0, #0x3
	str	r0, [r9, #MX7_DDRC_RFSHCTL3]

	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	mov	r1, #0x1
7:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	7b

	ldr	r0, =0x10f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800010f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r1, #0x1
8:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	8b

	mov	r0, #0xf0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	ldr	r0, =0x930
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800000f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_RFSHCTL3]
	mov	r0, #0x2
	str	r0, [r9, #MX7_DDRC_RFSHCTL3]

	mov	r1, #0x1
9:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	9b

	mov	r0, #0xf0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	ldr	r0, =0x930
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800000f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r1, #0x1
10:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	10b

	ldr	r0, =0x20f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	ldr	r0, =0x408
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800020f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r1, #0x1
11:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	11b

	ldr	r0, =0x10f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	ldr	r0, =0x4
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800010f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	ldr	r0, =0x0
	str	r0, [r9, #MX7_DDRC_DBG1]

	/* enable auto self-refresh */
	ldr	r0, [r9, #MX7_DDRC_PWRCTL]
	orr	r0, r0, #(1 << 0)
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	.endm

	.macro switch_to_533mhz_lpddr_end

   	/* LPDDR2 and LPDDR3 has different setting */
	cmp r6, #IMX_DDR_TYPE_LPDDR2
	beq	21f

	cmp	r7, #REV_1_1
	bne	23f

	ldr	r0, =0x08080808
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	ldr	r0, =0x0a0a0808
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]
	ldr	r0, =0x0a0a0a0a
	str	r0, [r8, #MX7_DDRPHY_CA_WLDSKEW_CON0]
	b	23f
21:
	cmp	r7, #REV_1_1
	bne	22f

	ldr	r0, =0x1c1c1c1c
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	ldr	r0, =0x30301c1c
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]
	ldr	r0, =0x30303030
	str	r0, [r8, #MX7_DDRPHY_CA_WLDSKEW_CON0]
	b	23f
22:
	ldr	r0, =0x08080808
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	ldr	r0, =0x0808
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]
23:
	ldr	r0, =0x11000008
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]
	ldr	r0, =0x10000008
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]

	mov	r1, #0x4
24:
	ldr	r0, [r8, #MX7_DDRPHY_MDLL_CON1]
	and	r0, r0, r1
	cmp	r0, r1
	bne	24b

	.endm

	.macro switch_to_533mhz
	cmp r6, #IMX_DDR_TYPE_DDR3
	beq 101f

	/* LPDDR3 or LPDDR3 switch to 533 MHZ beginning */
	ldr	r0, =0x10210100
	str	r0, [r8, #MX7_DDRPHY_PHY_CON1]

	ldr	r0, =0x00200038
	str	r0, [r8, #MX7_DDRPHY_RFSHTMG]

	b	102f
101:
	switch_to_533mhz_ddr3_start

102:
	/* dram root set to from dram main, div by 2 */
	ldr	r0, =0x10000001
	ldr r1, =CCM_TARGET_ROOT49
	str	r0, [r10, r1]

	ldr	r0, =0x1010007e
	str	r0, [r8, #MX7_DDRPHY_MDLL_CON0]

	ldr	r0, =0x10000008
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]

	ldr	r0, =0x08080808
	str	r0, [r8, #MX7_DDRPHY_OFFSETR_CON0]
	str	r0, [r8, #MX7_DDRPHY_OFFSETR_CON1]
	mov	r0, #0x8
	str	r0, [r8, #MX7_DDRPHY_OFFSETR_CON2]

	ldr	r0, =0x08080808
	str	r0, [r8, #MX7_DDRPHY_OFFSETW_CON0]
	str	r0, [r8, #MX7_DDRPHY_OFFSETW_CON1]
	mov	r0, #0x8
	str	r0, [r8, #MX7_DDRPHY_OFFSETW_CON2]

	cmp	r6, #IMX_DDR_TYPE_DDR3
	beq	103f

	switch_to_533mhz_lpddr_end
	b	104f
103:
	switch_to_533mhz_ddr3_end

104:
	.endm


	.macro switch_below_100mhz_ddr3_start

	mov	r0, #0x2
	str	r0, [r9, #MX7_DDRC_DBG1]

	mov	r1, #(0x36 << 24)
31:
	ldr	r0, [r9, #MX7_DDRC_DBGCAM]
	and	r0, r0, r1
	cmp	r0, r1
	bne	31b

	mov	r1, #0x1
32:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	32b

	ldr	r0, =0x10f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800010f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r1, #0x1
33:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	33b

	ldr	r0, =0x20f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	mov	r0, #0x8
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800020f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r1, #0x1
34:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	34b

	ldr	r0, =0x10f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	ldr	r0, =0x1
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800010f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r0, #0x20
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	mov	r1, #0x23
35:
	ldr	r0, [r9, #MX7_DDRC_STAT]
	and	r0, r0, r1
	cmp	r0, r1
	bne	35b

	mov r0, #0x0
	str	r0, [r9, #MX7_DDRC_SWCTL]

	ldr	r0, =0x03048001
	str	r0, [r9, #MX7_DDRC_MSTR]

	mov	r0, #0x1
	str	r0, [r9, #MX7_DDRC_SWCTL]

	mov	r1, #0x1
36:
	ldr	r0, [r9, #MX7_DDRC_SWSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	bne	36b

	ldr	r0, =0x10010100
	str	r0, [r8, #MX7_DDRPHY_PHY_CON1]

	.endm

	.macro switch_below_100mhz_ddr3_end

	ldr	r0, =0x1100007f
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]
	ldr	r0, =0x1000007f
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]

	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	mov	r1, #0x1
37:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	37b

	mov	r0, #0xf0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]
	ldr	r0, =0x820
	str	r0, [r9, #MX7_DDRC_MRCTRL1]
	ldr	r0, =0x800000f0
	str	r0, [r9, #MX7_DDRC_MRCTRL0]

	mov	r1, #0x1
38:
	ldr	r0, [r9, #MX7_DDRC_MRSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	38b

	ldr	r0, =0x800020
	str	r0, [r9, #MX7_DDRC_ZQCTL0]

	ldr	r0, =0x0
	str	r0, [r9, #MX7_DDRC_DBG1]

	/* enable auto self-refresh */
	ldr	r0, [r9, #MX7_DDRC_PWRCTL]
	orr	r0, r0, #(1 << 0)
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	.endm


	.macro switch_below_100mhz

	cmp	r6, #IMX_DDR_TYPE_DDR3
	beq	203f

	cmp	r6, #IMX_DDR_TYPE_LPDDR2
	beq	201f

	/* LPDDR3 */
	mov	r0, #0x100
	str	r0, [r8, #MX7_DDRPHY_PHY_CON1]
	b	202f

201:
	/* LPDDR2 */
	ldr	r0, =0x10010100
	str	r0, [r8, #MX7_DDRPHY_PHY_CON1]

202:
	ldr	r0, =0x00020038
	str	r0, [r8, #MX7_DDRPHY_RFSHTMG]

	b	204f

203:
	switch_below_100mhz_ddr3_start

204:
	/* Get the Frequency to switch to */
	ldr	r0, [r12, #BUSFREQ_INFO_FREQ]
	ldr	r1, =FREQ_24MHZ
	cmp	r0, r1
	beq	25f

	ldr	r0, =0x000B000D
	str	r0, [r9, #MX7_DDRC_RFSHTMG]
	b	205f

25:
	ldr	r0, =0x00030004
	str	r0, [r9, #MX7_DDRC_RFSHTMG]

	/* dram alt sel set to OSC */
	ldr	r0, =0x10000000
	ldr	r1, =CCM_TARGET_ROOT65
	str	r0, [r10, r1]
	/* dram root set to from dram alt, div by 1 */
	ldr	r0, =0x11000000
	ldr	r1, =CCM_TARGET_ROOT49
	str	r0, [r10, r1]
	b	206f

205:
	/* dram alt sel set to pfd0_392m */
	ldr	r0, =0x15000000
	ldr	r1, =CCM_TARGET_ROOT65
	str	r0, [r10, r1]
	/* dram root set to from dram alt, div by 4 */
	ldr	r0, =0x11000003
	ldr	r1, =CCM_TARGET_ROOT49
	str	r0, [r10, r1]
206:
	ldr	r0, =0x202ffd0
	str	r0, [r8, #MX7_DDRPHY_MDLL_CON0]

	cmp	r6, #IMX_DDR_TYPE_DDR3
	ldreq	r0, =0x1000007f
	movne	r0, #0x7f
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]

	ldr	r0, =0x7f7f7f7f
	str	r0, [r8, #MX7_DDRPHY_OFFSETR_CON0]
	str	r0, [r8, #MX7_DDRPHY_OFFSETR_CON1]
	mov	r0, #0x7f
	str	r0, [r8, #MX7_DDRPHY_OFFSETR_CON2]

	ldr	r0, =0x7f7f7f7f
	str	r0, [r8, #MX7_DDRPHY_OFFSETW_CON0]
	str	r0, [r8, #MX7_DDRPHY_OFFSETW_CON1]
	mov	r0, #0x7f
	str	r0, [r8, #MX7_DDRPHY_OFFSETW_CON2]

	cmp	r7, #REV_1_1
	bne	207f

	mov	r0, #0x0
	str	r0, [r8, #MX7_DDRPHY_CA_WLDSKEW_CON0]
	ldr	r0, =0x60606060
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	ldr	r0, =0x00006060
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]
	b	208f
207:
	mov	r0, #0x0
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON0]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON1]
	str	r0, [r8, #MX7_DDRPHY_CA_DSKEW_CON2]

208:
	cmp	r6, #IMX_DDR_TYPE_DDR3
	beq	209f

	/* LPDDR3 or LPDDR2 switch below 100 MHZ completion */
	ldr	r0, =0x100007f
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]
	mov	r0, #0x7f
	str	r0, [r8, #MX7_DDRPHY_OFFSETD_CON0]

	b	210f

209:
	switch_below_100mhz_ddr3_end

210:
	.endm

	.macro prepare_lpddr

	/* disable port */
	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_MP_PCTRL0]

	/* wait port busy done */
	ldr	r1, =0x10001
301:
	ldr	r0, [r9, #MX7_DDRC_MP_PSTAT]
	and	r0, r0, r1
	cmp	r0, #0
	bne	301b

	mov	r0, #0x20
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	mov	r1, #0x23
302:
	ldr	r0, [r9, #MX7_DDRC_STAT]
	and	r0, r0, r1
	cmp	r0, r1
	bne	302b

	mov	r0, #0x1
	str	r0, [r9, #MX7_DDRC_DBG1]

	mov	r1, #(0x3 << 28)
303:
	ldr	r0, [r9, #MX7_DDRC_DBGCAM]
	and	r0, r0, r1
	cmp	r0, r1
	bne	303b

	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_SWCTL]

	str	r0, [r9, #MX7_DDRC_DFIMISC]

	mov	r0, #0x1
	str	r0, [r9, #MX7_DDRC_SWCTL]

	mov r1, #0x1
304:
	ldr	r0, [r9, #MX7_DDRC_SWSTAT]
	and	r0, r0, r1
	cmp	r0, r1
	bne	304b

	.endm

	.macro done_lpddr

	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	mov	r1, #0x3
311:
	ldr	r0, [r9, #MX7_DDRC_STAT]
	and	r0, r0, r1
	cmp	r0, r1
	beq	311b

	mov	r0, #0x0
	str	r0, [r9, #MX7_DDRC_DBG1]

	mov	r0, #0x1
	str	r0, [r9, #MX7_DDRC_MP_PCTRL0]

	/* enable auto self-refresh */
	ldr	r0, [r9, #MX7_DDRC_PWRCTL]
	orr	r0, r0, #(1 << 0)
	str	r0, [r9, #MX7_DDRC_PWRCTL]

	.endm

/**
 * @brief   Switch the i.MX7 DDR in self-refresh to
 *          change its clock and exit self-refresh
 *        IRQs must be disabled.
 *
 * @param[in/out] busfreq_info  busfreq data
 */
.align 3
FUNC imx7_ddr_freq_change , :
UNWIND( .fnstart)
	push	{r1-r12, lr}

	/* Save the input parameters */
	push	{r0}

	/* Disable D$ */
	ldr	r11, =cpu_mmu_disable_dcache
	mov	lr, pc
	mov	pc, r11

	/* Disable Prediction */
	read_sctlr	r2
	bic	r2, r2, #SCTLR_Z
	write_sctlr	r2
	dsb
	isb

	pop	{r12}

	/* Keep r8 to r12 as is */
	ldr	r8,  [r12, #BUSFREQ_INFO_DDRC_PHY_BASE]
	ldr	r9,  [r12, #BUSFREQ_INFO_DDRC_BASE]
	ldr	r10, [r12, #BUSFREQ_INFO_CCM_BASE]
	ldr	r11, [r12, #BUSFREQ_INFO_IOMUX_BASE]

	/* Make sure TLB preloaded */
	ldr	r0, [r8]
	ldr	r0, [r9]
	ldr	r0, [r10]
	ldr	r0, [r11]

	/* Get the device revision - keep it in r7 */
	ldrh	r7, [r12, #BUSFREQ_INFO_REV]

	/* Get the DDR Type in r6 - keep it in r6 */
	ldrh	r6, [r12, #BUSFREQ_INFO_DDR_TYPE]
	cmp	r6, #IMX_DDR_TYPE_DDR3
	beq	bypass_prepare_lpddr

	prepare_lpddr

bypass_prepare_lpddr:
	/* Get the Bus Freq to switch on */
	ldr	r0, [r12, #BUSFREQ_INFO_FREQ]
	ldr	r1, =FREQ_100MHZ
	cmp	r0, r1
	bgt	set_freq_to_533mhz

	switch_below_100mhz
	b	setup_lpddr_done

set_freq_to_533mhz:
	switch_to_533mhz

setup_lpddr_done:
	cmp	r6, #IMX_DDR_TYPE_DDR3
	beq	bypass_done_lpddr

	/* Complete LPDDR switch */
	done_lpddr

bypass_done_lpddr:

	/* Enable D$ and Prediction */
	read_sctlr	r2
	mov	r3, #SCTLR_C
	add	r3, r3, #SCTLR_Z
	orr	r2, r2, r3
	write_sctlr	r2
	isb

 	/* restore registers */
	pop	{r1-r12, lr}
	mov	pc, lr

	/* Ensure that all constant will be stored here */
	.ltorg

	.equ	FREQ_100MHZ, 100000000
	.equ	FREQ_24MHZ,  24000000

UNWIND( .fnend)
END_FUNC imx7_ddr_freq_change

FUNC get_imx7_ddr_freq_change_size , :
UNWIND( .fnstart)
	subs	r0, pc, #8
	ldr	r1, =imx7_ddr_freq_change
	sub	r0, r0, r1
	bx	lr
UNWIND( .fnend)
END_FUNC get_imx7_ddr_freq_change_size
