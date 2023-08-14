/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2020 NXP
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

/* Size in bytes */
#define DCP_CRC32_SIZE		 4
#define DCP_CONTEXT_BUFFER_SIZE	 208
#define DCP_CONTEXT_CHANNEL_SIZE 52

/* Constant for AES-CMAC algorithm */
#define DCP_AES128CMAC_RB_CONST 0x87

/* Others defines */
#define DCP_MAX_TIMEOUT		10
#define DCP_SRAM_KEY_NB_SUBWORD 4
#define DCP_CLK_ENABLE_MASK	GENMASK_32(11, 10)
#define DCP_MSB_INT8		BIT(7)

#endif /* __LOCAL_H__ */
