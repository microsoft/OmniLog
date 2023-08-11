/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Manufacturing Protection header.
 */
#ifndef __CAAM_MP_H__
#define __CAAM_MP_H__

#ifdef CFG_NXP_CAAM_MP_DRV
/*
 * Initialize the MP module and generate the private key
 *
 * @ctrl_addr   Controller base address
 */
enum caam_status caam_mp_init(vaddr_t ctrl_addr);
#else
static inline enum caam_status caam_mp_init(vaddr_t ctrl_addr __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_MP_DRV */

#endif /* __CAAM_MP_H__ */
