/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * Brief   CAAM Secure Memory module header.
 */
#ifndef __CAAM_SM_H__
#define __CAAM_SM_H__

#include <caam_jr.h>
#include <drivers/caam/crypto_extension.h>

/*
 * Secure Memory data
 */
struct sm_page_addr {
	paddr_t paddr;   /* Secure memory base address */
	vaddr_t vaddr;   /* Secure memory virtual base address */
};

/*
 * Secure Memory Access Permission allowed
 */
#define SM_GRP_READ	BIT32(0) /* Read allowed */
#define SM_GRP_WRITE	BIT32(1) /* Write allowed */
#define SM_GRP_TDO	BIT32(2) /* Trusted Descriptor override allowed */
#define SM_GRP_BLOB	BIT32(3) /* Export/Import Secure Memory blobs allowed */

#ifdef CFG_NXP_CAAM_SM_DRV
/*
 * CAAM Secure memory module initialization
 *
 * @jrcfg  JR configuration structure
 */
enum caam_status caam_sm_init(struct caam_jrcfg *jrcfg);

/*
 * Allocate page(s) to one partition in the CAAM secure memory.
 * Reset the group access and permission access to remove restrictions.
 *
 * @sm_page  Secure Memory page
 * @sm_addr  [out] Secure Memory page addresses
 */
enum caam_status caam_sm_alloc(struct crypto_sm_page *sm_page,
			       struct sm_page_addr *sm_addr);

/*
 * Set the Secure Memory group 1 and group 2 access rights to allocated
 * partition and lock configuration.
 *
 * @sm_page    Secure Memory page
 * @grp1_perm  Group 1 Permission value
 * @grp2_perm  Group 2 Permission value
 */
enum caam_status caam_sm_set_access_perm(struct crypto_sm_page *sm_page,
					 unsigned int grp1_perm,
					 unsigned int grp2_perm);

/*
 * Free a Secure Memory pages
 *
 * @sm_page    Secure Memory page
 */
TEE_Result caam_sm_free_page(struct crypto_sm_page *sm_page);

#else
static inline enum caam_status caam_sm_init(struct caam_jrcfg *jrcfg __unused)
{
	return CAAM_NO_ERROR;
}
#endif /* CFG_NXP_CAAM_SM_DRV */
#endif /* __CAAM_SM_H__ */
