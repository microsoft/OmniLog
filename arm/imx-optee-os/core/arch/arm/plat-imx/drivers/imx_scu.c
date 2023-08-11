// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2020 NXP
 *
 */

#include <imx.h>
#include <initcall.h>
#include <io.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_def.h>
#include <kernel/pm.h>
#include <mm/core_memprot.h>

static TEE_Result scu_configure(void)
{
	vaddr_t scu_base = core_mmu_get_va(SCU_BASE, MEM_AREA_IO_SEC);

	if (!scu_base)
		return TEE_ERROR_GENERIC;

	/* SCU config */
	io_write32(scu_base + SCU_INV_SEC, SCU_INV_CTRL_INIT);
	io_write32(scu_base + SCU_SAC, SCU_SAC_CTRL_INIT);
	io_write32(scu_base + SCU_NSAC, SCU_NSAC_CTRL_INIT);

	/* SCU enable */
	io_write32(scu_base + SCU_CTRL, io_read32(scu_base + SCU_CTRL) | 0x1);

	return TEE_SUCCESS;
}

static TEE_Result pm_enter_resume(enum pm_op op, uint32_t pm_hint __unused,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_RESUME) {
		scu_configure();
		dcache_op_all(DCACHE_OP_CLEAN_INV);
	}
	return TEE_SUCCESS;
}

static TEE_Result scu_init(void)
{
	scu_configure();
	register_pm_driver_cb(pm_enter_resume, NULL);

	return TEE_SUCCESS;
}

driver_init(scu_init);
