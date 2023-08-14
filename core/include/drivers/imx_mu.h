/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */

#ifndef __IMX_MU_H__
#define __IMX_MU_H__

#include <types_ext.h>
#include <util.h>

#define MU_ATR0_OFFSET1 0x0
#define MU_ATR(n)	(0x0 + (n) * (4))
#define MU_NB_TR	4
#define MU_ARR0_OFFSET1 0x10
#define MU_ARR(n)	(0x10 + (n) * (4))
#define MU_NB_RR	4
#define MU_ASR_OFFSET	0x20
#define MU_ACR_OFFSET	0x24

/* Processor general purpose interrupt n is pending */
#define MU_SR_GIP(n) SHIFT_U32(1, 28 + (n))
/* RRn register has received data from TRn register and is ready to be read */
#define MU_SR_RF(n) SHIFT_U32(1, 27 - (n))

/* TRn register is empty */
#define MU_SR_TE(n) SHIFT_U32(1, 23 - (n))
/* The other-side processor is out of reset */
#define MU_SR_RDIP BIT32(9)
/* Processor initiated flags update, processing */
#define MU_SR_FUP BIT32(8)
/* The other-side processor of the MU is in reset */
#define MU_SR_BRS BIT32(7)
/* Processor event is pending */
#define MU_SR_EP BIT32(4)
/* Fn bit in other-side CR register is written 1 */
#define MU_SR_F(n) BIT32(n)
/* Enables Processor General Interrupt n */
#define MU_CR_GIE(n)	SHIFT_U32(1, 28 + (n))
#define MU_CR_GIEn_MASK GENMASK_32(31, 28)
/* Enables Processor Receive Interrupt n */
#define MU_CR_RIE(n)	SHIFT_U32(1, 24 + (n))
#define MU_CR_RIEn_MASK GENMASK_32(27, 24)
/* Enables Processor Transmit Interrupt n */
#define MU_CR_TIE(n)	SHIFT_U32(1, 20 + (n))
#define MU_CR_TIEn_MASK GENMASK_32(23, 20)
/* Processor General Interrupt n is requested to the other-side Processor */
#define MU_CR_GIR(n)	SHIFT_U32(1, 16 + (n))
#define MU_CR_GIRn_MASK GENMASK_32(19, 16)
/*
 * Enables Processor General Purpose Interrupt 3 request due to the other-side
 * Processor reset de-assertion to the Processor
 */
#define MU_CR_RDIE BIT32(6)
/* Asserts the Processor MU reset */
#define MU_CR_MUR BIT32(5)
/* Assert Hardware reset to the other-side Processor */
#define MU_CR_BHR BIT32(4)
/* Asserts the Processor MU reset */
#define MU_CR_F(n)    BIT32(n)
#define MU_CR_Fn_MASK GENMASK_32(2, 0)

#define MU_SIZE 0x10000

/*
 * Clear GIEn, RIEn, TIEn, GIRn and Fn registers
 *
 * @base   Base address of the MU
 */
void mu_init(vaddr_t base);

/*
 * Send a message through MU
 *
 * @base    Base address of the MU
 * @index   Index of the TR register
 * @msg     Message to send
 */
void mu_send_msg(vaddr_t base, uint32_t index, uint32_t msg);

/*
 * Receive a message through MU
 *
 * @base    Base address of the MU
 * @index   Index of the RR register
 * @msg     [out] Received message
 */
void mu_receive_msg(vaddr_t base, uint32_t index, uint32_t *msg);

#endif /* __IMX_MU_H__ */
