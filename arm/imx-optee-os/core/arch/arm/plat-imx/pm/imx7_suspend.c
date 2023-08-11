// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2020 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 */

#include <arm.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx.h>
#include <imx_pm.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <sm/sm.h>
#include <sm/pm.h>
#include <sm/psci.h>
#include <stdint.h>

int imx7_cpu_suspend(uint32_t power_state __unused, uintptr_t entry,
		     uint32_t context_id __unused, struct sm_nsec_ctx *nsec)
{
	uint32_t suspend_ocram_base = core_mmu_get_va(
						imx_get_ocram_tz_start_addr() +
						SUSPEND_OCRAM_OFFSET,
							MEM_AREA_TEE_COHERENT);
	struct imx7_pm_info *p = (struct imx7_pm_info *)suspend_ocram_base;
	int ret;

	sm_save_unbanked_regs(&nsec->ub_regs);

	ret = sm_pm_cpu_suspend((uint32_t)p, (int (*)(uint32_t))
				(suspend_ocram_base + sizeof(*p)));
	/*
	 * Sometimes sm_pm_cpu_suspend may not really suspended,
	 * we need to check it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	sm_restore_unbanked_regs(&nsec->ub_regs);

	/*
	 * Call the Wakeup Late function to restore some
	 * HW configuration (e.g. TZASC)
	 */
	plat_cpu_wakeup_late();

	/* Set entry for back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

	DMSG("=== Back from Suspended ===\n");

	return 0;
}
