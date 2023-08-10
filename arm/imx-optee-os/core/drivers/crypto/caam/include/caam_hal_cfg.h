/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM Configuration header.
 */
#ifndef __CAAM_HAL_CFG_H__
#define __CAAM_HAL_CFG_H__

#include <caam_jr.h>

#if defined(CFG_MX8MM) || defined(CFG_MX8MN) || defined(CFG_MX8MP) ||          \
	defined(CFG_MX8MQ)
#define DTB_JR_PATH "/soc@0/bus@30800000/crypto@30900000/jr"
#elif defined(CFG_MX8QM) || defined(CFG_MX8QXP) || defined(CFG_MX8DXL)
#define DTB_JR_PATH "/bus@31400000/crypto@31400000/jr"
#else
/* Currently not supported on i.MX 6 and 7 */
#define DTB_JR_PATH ""
#endif

/*
 * Returns the Job Ring Configuration to be used by the TEE
 *
 * @jrcfg   [out] Job Ring Configuration
 *
 * Returns:
 * CAAM_NO_ERROR   Success
 * CAAM_FAILURE    An error occurred
 */
enum caam_status caam_hal_cfg_get_conf(struct caam_jrcfg *jrcfg);

/*
 * Setup the Non-Secure Job Ring
 * Soc specific function
 *
 * @jrcfg   Job Ring configuration
 */
void caam_hal_cfg_setup_nsjobring(struct caam_jrcfg *jrcfg);

/*
 * Setup the Non-Secure Job Ring
 * Common function
 *
 * @jrcfg   Job Ring configuration
 */
void caam_hal_cfg_common_setup_nsjobring(struct caam_jrcfg *jrcfg);

#ifdef CFG_DT
/*
 * Returns the Job Ring configuration to be used by the TEE
 *
 * @fdt         Device Tree handle
 * @ctrl_base   [out] CAAM Controller base address
 */
void caam_hal_cfg_get_ctrl_dt(void *fdt, vaddr_t *ctrl_base);

/*
 * Returns the Job Ring configuration to be used by the TEE
 *
 * @fdt     Device Tree handle
 * @jrcfg   [out] Job Ring configuration
 */
void caam_hal_cfg_get_jobring_dt(void *fdt, struct caam_jrcfg *jrcfg);

/*
 * Disable the DT node related to the Job Ring used by secure world
 *
 * @fdt     Device Tree handle
 * @jrcfg   Job Ring configuration
 */
void caam_hal_cfg_disable_jobring_dt(void *fdt, struct caam_jrcfg *jrcfg);
#else
static inline void caam_hal_cfg_get_ctrl_dt(void *fdt __unused,
					    vaddr_t *ctrl_base)
{
	*ctrl_base = 0;
}

static inline void
caam_hal_cfg_get_jobring_dt(void *fdt __unused,
			    struct caam_jrcfg *jrcfg)
{
	jrcfg->offset = 0;
	jrcfg->it_num = 0;
}

static inline void
caam_hal_cfg_disable_jobring_dt(void *fdt __unused,
				struct caam_jrcfg *jrcfg __unused)
{
}
#endif /* CFG_DT */

#endif /* __CAAM_HAL_CFG_H__ */
