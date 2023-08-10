// SPDX-License-Identifier: BSD-2-Clause
/**
 * @copyright 2018 NXP
 *
 * @file    busfreq.c
 *
 * @brief   Implementation of the bus frequency scaling.\n
 *          Interface and initialization.
 */

/* Global includes */
#include <initcall.h>
#include <kernel/boot.h>
#include <libfdt.h>
#include <tee_api_types.h>
#include <trace.h>

/* Platform includes */
#include <imx.h>
#include <imx_busfreq.h>

/* Local include */
#include "busfreq_imx6.h"
#include "busfreq_imx7.h"

#ifndef CFG_IMX6
__weak TEE_Result imx6_busfreq_change(uint32_t freq __unused,
		uint32_t dll_off __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

__weak TEE_Result imx6_busfreq_init(void)
{
	return TEE_ERROR_GENERIC;
}
#endif
#ifndef CFG_IMX7
__weak TEE_Result imx7_busfreq_change(uint32_t freq __unused,
		uint32_t dll_off __unused)
{
	return TEE_ERROR_NOT_SUPPORTED;
}

__weak TEE_Result imx7_busfreq_init(void)
{
	return TEE_ERROR_GENERIC;
}
#endif

/**
 * @brief   Change the bus frequency on any i.MX devices
 *          to the requested frequency \a freq and
 *          switch DLL off is \a dll_off = 1
 *
 * @param[in] freq     Frequency to switch to
 * @param[in] dll_off  switch DLL off or not
 *
 * @retval  TEE_SUCCESS              No error
 * @retvql  TEE_ERROR_NOT_SUPPORTED  Feature not supported
 */
TEE_Result busfreq_change(uint32_t freq, uint32_t dll_off)
{
	TEE_Result ret = TEE_ERROR_NOT_SUPPORTED;

	if (soc_is_imx6())
		ret = imx6_busfreq_change(freq, dll_off);
	else if (soc_is_imx7ds())
		ret = imx7_busfreq_change(freq, dll_off);

	return ret;
}

#ifdef CFG_DT
/**
 * @brief   Add the busfreq property into the "/firmware/optee"
 *          node.
 *
 * @retval 0    if success
 * @retval (-1) otherwise
 */
static int dt_busfreq(void)
{
	void *fdt = get_dt();
	int  offs;
	int  ret;

	offs = fdt_path_offset(fdt, "/firmware/optee");

	if (offs < 0) {
		EMSG("OP-TEE Device Tree doesn't exist!\n");
		return (-1);
	}

	ret = fdt_setprop_u32(fdt, offs, "busfreq", 1);
	if (ret < 0)
		return (-1);

	return 0;
}
#else
static int dt_busfreq(void)
{
	return 0;
}
#endif
/**
 * @brief   Allocation and initialization of the OCRAM
 *          into which memory frequency change function
 *          will be executed
 *
 * @retval  TEE_SUCCESS         Success
 * @retval  TEE_ERROR_GENERIC   Generic Error
 */
static TEE_Result busfreq_init(void)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	if (soc_is_imx6())
		ret = imx6_busfreq_init();
	else if (soc_is_imx7ds())
		ret = imx7_busfreq_init();

	if (ret == TEE_SUCCESS) {
		if (dt_busfreq()) {
			EMSG("Failed to config Bus Frequency");
			ret = TEE_ERROR_GENERIC;
		}
	}

	return ret;
}

service_init(busfreq_init);
