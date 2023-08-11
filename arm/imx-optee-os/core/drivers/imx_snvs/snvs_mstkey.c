// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2019 NXP
 *
 * @file    snvs_mstkey.c
 *
 * @brief   Device Master key selection
 */
/* Global includes */
#include <drivers/imx_snvs.h>
#include <io.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <platform_config.h>

/* Platform includes */
#include <imx.h>

/**
 * @brief   Checks if the master key is the OTPMK
 *
 * @retval true if master key is OTPMK
 * @retval false otherwise
 */
static inline bool is_otpmk_selected(void)
{
	vaddr_t snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);
	uint32_t hp_mks;
	uint32_t lp_mks;

	hp_mks = io_read32(snvs_base + SNVS_HPCOMR);
	hp_mks &= ~BM_SNVS_HPCOMR_MKS_EN;

	/*
	 * If Master Key is function of the LP MASTER_KEY_SEL
	 * field
	 */
	if (hp_mks) {
		lp_mks = io_read32(snvs_base + SNVS_LPMKCR);
		lp_mks &= ~BM_SNVS_LP_MKCR_MKS_SEL;

		if (lp_mks != 0)
			return false;
	}

	return true;
}

/**
 * @brief   Check if master key selection is locked
 *
 * @retval true if locked
 * @retval false otherwise
 */
static inline bool is_mks_locked(void)
{
	vaddr_t snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);
	uint32_t hp_lr;
	uint32_t lp_lr;

	hp_lr = io_read32(snvs_base + SNVS_HPLR);
	lp_lr = io_read32(snvs_base + SNVS_LPLR);

	if ((hp_lr & BM_SNVS_HPLR_MKS_SL) || (lp_lr & BM_SNVS_LPLR_MKS_HL))
		return true;

	return false;
}

/**
 * @brief   Set the Master key to use OTPMK and lock it. If the
 *          Master Key is already locked returns.
 *
 * @retval 0    success
 * @retval (-1) Master Key is already locked
 */
static inline int set_mks_otpmk(void)
{
	vaddr_t snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);

	if (is_mks_locked())
		return (-1);

	io_mask32(snvs_base + SNVS_HPCOMR, BM_SNVS_HPCOMR_MKS_EN,
			BM_SNVS_HPCOMR_MKS_EN);
	io_mask32(snvs_base + SNVS_LPMKCR, 0, BM_SNVS_LP_MKCR_MKS_SEL);

	io_mask32(snvs_base + SNVS_HPLR, BM_SNVS_HPLR_MKS_SL,
			BM_SNVS_HPLR_MKS_SL);
	io_mask32(snvs_base + SNVS_LPLR, BM_SNVS_LPLR_MKS_HL,
			BM_SNVS_LPLR_MKS_HL);

	return 0;
}

/**
 * @brief   Check if OTPMK is valid
 *
 * @retval true if valid
 * @retval false otherwise
 */
static inline bool is_otpmk_valid(void)
{
	vaddr_t snvs_base = core_mmu_get_va(SNVS_BASE, MEM_AREA_IO_SEC);

	uint32_t hp_status;

	hp_status = io_read32(snvs_base + SNVS_HPSTATUS);

	hp_status &= (BM_SNVS_HPSTATUS_OTPMK_ZERO |
			BM_SNVS_HPSTATUS_OTPMK_SYND);

	if (hp_status) {
		EMSG("OTPK Key is not valid");
		return false;
	}

	return true;

}

/**
 * @brief   Set the OTPMK Key as Master key.
 *          If device is a closed device and OTMPK can not be set
 *          system stop in panic.
 *          If device is NOT a closed device and OTPMK can not be
 *          set, continue anyway.
 */
void snvs_set_master_otpmk(void)
{
	int status = (-1);

	if (is_otpmk_valid()) {
		if (is_otpmk_selected() && is_mks_locked())
			return;

		status = set_mks_otpmk();
	}

	if (!imx_is_device_closed() && (status != 0)) {
		IMSG("*******************************************************");
		IMSG("* The system not in Trusted State                     *");
		IMSG("* This mode is only suitable for development purposes *");
		IMSG("* WARNING: Master Key is cannot be set to OTPMK       *");
		IMSG("* Continue without error                              *");
		IMSG("* Please do not go in production with this            *");
		IMSG("* All Secure storage object created in this state     *");
		IMSG("* will not be recoverable once this device will be    *");
		IMSG("* closed                                              *");
		IMSG("*******************************************************");
	} else if (imx_is_device_closed() && (status != 0)) {
		IMSG("*******************************************************");
		IMSG("* The system in Trusted State                         *");
		IMSG("* ERROR: Master Key is cannot be set to OTPMK         *");
		IMSG("* Stop Here                                           *");
		IMSG("*******************************************************");
		panic();
	}
}
