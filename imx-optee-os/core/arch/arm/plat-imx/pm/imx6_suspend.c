// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018, 2020 NXP
 *
 */
#include <arm.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx.h>
#include <imx_pl310.h>
#include <imx_pm.h>
#include <kernel/boot.h>
#include <kernel/cache_helpers.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <sm/optee_smc.h>
#include <sm/psci.h>
#include <sm/sm.h>
#include <sm/pm.h>

int (*suspend_func)(uint32_t);
struct imx_pm_asm_arg suspend_arg;

int imx6_cpu_suspend(uint32_t power_state __unused, uintptr_t entry,
		     uint32_t context_id __unused, struct sm_nsec_ctx *nsec)
{
	int ret;

	DMSG("=== Entering Suspend ===\n");

	/* Store non-sec ctx regs */
	sm_save_unbanked_regs(&nsec->ub_regs);

	ret = sm_pm_cpu_suspend((uint32_t)&suspend_arg, suspend_func);

	/*
	 * Sometimes sm_pm_cpu_suspend may not really suspended,
	 * we need to check it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	/* Restore register of different mode in secure world */
	sm_restore_unbanked_regs(&nsec->ub_regs);

	/*
	 * Call the Wakeup Late function to restore some
	 * HW configuration (e.g. TZASC)
	 */
	plat_cpu_wakeup_late();

	/* Back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

	/*
	 * There is no driver suspend/resume framework in op-tee.
	 * Add L2 code here, a bit different from OPTEE initialization
	 * when bootup. Now MMU is up, L1 enabled.
	 */
#ifdef CFG_PL310
	if (pl310_enabled(pl310_base()))
		return 0;

	arm_cl2_config(pl310_base());
	arm_cl2_invbyway(pl310_base());
	arm_cl2_enable(pl310_base());
	arm_cl2_invbyway(pl310_base());
#endif

	DMSG("=== Back from Suspended ===\n");

	return 0;
}
