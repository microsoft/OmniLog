// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2017-2018 NXP
 *
 */

#include <arm.h>
#include <console.h>
#include <drivers/imx_uart.h>
#include <io.h>
#include <imx_pl310.h>
#include <imx_pm.h>
#include <imx.h>
#include <kernel/boot.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/cache_helpers.h>
#include <kernel/tz_ssvce_pl310.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include <platform_config.h>
#include <stdint.h>
#include <string.h>
#include <sm/psci.h>
#include <sm/pm.h>
#include <util.h>

static int (*lowpower_idle_func)(uint32_t);
static struct imx_pm_asm_arg idle_arg;
static int lowpoweridle_init;

int imx6sx_cpuidle_init(void)
{
	uint32_t func_size;

	lowpower_idle_func = (int (*)(uint32_t))(pm_ocram_free_area);

	func_size = get_imx6sx_low_power_idle_size();

	idle_arg.pa_addr = virt_to_phys((void *)(vaddr_t)lowpower_idle_func);
	idle_arg.pm_info = suspend_arg.pm_info;

	memcpy((void *)(vaddr_t)lowpower_idle_func,
	       (void *)(vaddr_t)imx6sx_low_power_idle, func_size);

	pm_ocram_free_area += func_size;
	dcache_clean_range((void *)(vaddr_t)lowpower_idle_func,
			   (pm_ocram_free_area -
				(vaddr_t)lowpower_idle_func + 4));
	/*
	 * Note that IRAM IOSEC map, if changed to MEM map,
	 * need to flush cache
	 */
	icache_inv_all();

	lowpoweridle_init = 1;

	return 0;
}


int imx6sx_lowpower_idle(uint32_t power_state __unused,
			 uintptr_t entry,
			 uint32_t context_id __unused,
			 struct sm_nsec_ctx *nsec)
{
	int ret;

	vaddr_t scu_base = core_mmu_get_va(SCU_BASE, MEM_AREA_IO_SEC);

	DMSG("=== Enter Low Power Idle ===\n");
	if (!lowpoweridle_init) {
		imx6sx_cpuidle_init();
		lowpoweridle_init = 1;
	}

	/* Store non-sec ctx regs */
	sm_save_unbanked_regs(&nsec->ub_regs);

	ret = sm_pm_cpu_suspend((uint32_t)&idle_arg, lowpower_idle_func);


	/*
	 * Sometimes cpu_suspend may not really suspended, we need to check
	 * it's return value to restore reg or not
	 */
	if (ret < 0) {
		DMSG("=== Not suspended, GPC IRQ Pending ===\n");
		return 0;
	}

	/* Restore register of different mode in secure world */
	sm_restore_unbanked_regs(&nsec->ub_regs);

	/* SCU config */
	io_write32(scu_base + SCU_INV_SEC, SCU_INV_CTRL_INIT);
	io_write32(scu_base + SCU_SAC, SCU_SAC_CTRL_INIT);
	io_write32(scu_base + SCU_NSAC, SCU_NSAC_CTRL_INIT);

	/* SCU enable */
	io_write32(scu_base + SCU_CTRL,
		io_read32(scu_base + SCU_CTRL) | 0x1);

	/* after enable, flush cache to let other cores can see the data */
	dcache_op_all(DCACHE_OP_CLEAN_INV);

	/* Back to Linux */
	nsec->mon_lr = (uint32_t)entry;

	main_init_gic();

#ifdef CFG_PL310
	if (pl310_enabled(pl310_base()))
		return 0;

	arm_cl2_config(pl310_base());
	arm_cl2_invbyway(pl310_base());
	arm_cl2_enable(pl310_base());
	/* Do we need to lock? cpu performance? */
	/*arm_cl2_lockallways(pl310_base()); */
	arm_cl2_invbyway(pl310_base());
#endif

	DMSG("=== Back from Low Power Idle ===\n");

	return 0;
}
