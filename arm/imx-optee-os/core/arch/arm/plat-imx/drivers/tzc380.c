// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 Pengutronix
 * All rights reserved.
 * Copyright 2019 NXP
 *
 * Rouven Czerwinski <entwicklung@pengutronix.de>
 */

#include <config.h>
#include <drivers/tzc380.h>
#include <imx-regs.h>
#include <imx.h>
#include <initcall.h>
#include <kernel/pm.h>
#include <kernel/panic.h>
#include <mm/core_memprot.h>
#include <mm/generic_ram_layout.h>

register_phys_mem(MEM_AREA_IO_SEC, TZASC_BASE, TZASC_SIZE);
#ifdef TZASC2_BASE
register_phys_mem(MEM_AREA_IO_SEC, TZASC2_BASE, TZASC2_SIZE);
#else
#define TZASC2_BASE	0
#endif

static void imx_configure_tzasc(void)
{
	vaddr_t addr[2] = {0};
	int end = 1;
	int i = 0;

	addr[0] = core_mmu_get_va(TZASC_BASE, MEM_AREA_IO_SEC);

	if (IS_ENABLED(CFG_MX6Q) || IS_ENABLED(CFG_MX6D) ||
	    IS_ENABLED(CFG_MX6DL)) {
		assert(TZASC2_BASE != 0);
		addr[1] = core_mmu_get_va(TZASC2_BASE, MEM_AREA_IO_SEC);
		end = 2;
	}

	for (i = 0; i < end; i++) {
		uint8_t region = 1;

		tzc_init(addr[i]);

		/*
		 * It is possible to access memory protected by the TZASC in
		 * case the DDR installed is smaller than the memory space
		 * supported by the controller. (Ref: RM, section about the
		 * TZASC: "Address Mapping in various memory mapping modes").
		 *
		 * Without aliasing protection it is possible to use an address
		 * outside of the DDR ranged and bypass TZASC protection.
		 */
		tzc_configure_region(0, 0x00000000, TZC_ATTR_SP_S_RW);

		region =
			tzc_auto_configure(CFG_IMX_TZC_NSEC_START, CFG_DDR_SIZE,
					   TZC_ATTR_SP_NS_RW, region);
		region = tzc_auto_configure(CFG_IMX_TZC_SEC_START,
					    CFG_TZDRAM_SIZE, TZC_ATTR_SP_S_RW,
					    region);
		region = tzc_auto_configure(CFG_IMX_TZC_SHMEM_START,
					    CFG_SHMEM_SIZE, TZC_ATTR_SP_ALL,
					    region);

		DMSG("Action register: 0x%" PRIx32, tzc_get_action());
	}

	tzc_dump_state();
}

static TEE_Result pm_enter_resume(enum pm_op op, uint32_t pm_hint __unused,
		const struct pm_callback_handle *pm_handle __unused)
{
	if (op == PM_OP_RESUME)
		imx_configure_tzasc();

	return TEE_SUCCESS;
}

static TEE_Result tzasc_init(void)
{
	imx_configure_tzasc();
	register_pm_driver_cb(pm_enter_resume, NULL);

	return TEE_SUCCESS;
}

driver_init(tzasc_init);
