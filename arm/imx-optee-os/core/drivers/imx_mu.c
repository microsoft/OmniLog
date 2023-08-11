// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 */
#include <drivers/imx_mu.h>
#include <io.h>

void mu_init(vaddr_t base)
{
	uint32_t clear_mask = MU_CR_GIEn_MASK | MU_CR_RIEn_MASK |
			      MU_CR_TIEn_MASK | MU_CR_GIRn_MASK | MU_CR_Fn_MASK;

	/* Clear GIEn, RIEn, TIEn, GIRn and Fn */
	io_clrbits32(base + MU_ACR_OFFSET, clear_mask);
}

void mu_send_msg(vaddr_t base, uint32_t index, uint32_t msg)
{
	uint32_t reg = 0;

	/* Wait TX register to be empty */
	do {
		reg = io_read32(base + MU_ASR_OFFSET);
		reg &= MU_SR_TE(index);
	} while (!reg);

	/* Write message in TX register */
	io_write32(base + MU_ATR(index), msg);
}

void mu_receive_msg(vaddr_t base, uint32_t index, uint32_t *msg)
{
	uint32_t reg = 0;

	/* Wait RX register to be full */
	do {
		reg = io_read32(base + MU_ASR_OFFSET);
		reg &= MU_SR_RF(index);
	} while (!reg);

	*msg = io_read32(base + MU_ARR(index));
}
