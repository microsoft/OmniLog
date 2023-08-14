// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2019 NXP
 *
 */

#include <kernel/pm.h>
#include <kernel/thread.h>
#include <imx.h>
#include <imx_pm.h>
#include <trace.h>
#include <util.h>

/**
 * @brief   Handler for cpu resume
 *
 * @param[in] a0   Max power level powered down
 * @param[in] a1   Unusued
 *
 * @retval TEE_SUCCESS         Success
 * @retval TEE_ERROR_GENERIC   Generic error
 */
unsigned long thread_cpu_resume_handler(unsigned long a0,
						unsigned long a1 __unused)
{
	TEE_Result retstatus = TEE_SUCCESS;

	/* a0 is the highest power level which was powered down.
	 * This can be:
	 *	PM_CORE_LEVEL i.e. "0" in case of Core level
	 *	PM_CLUSTER_LEVEL i.e. "1" in case of Cluster level
	 *	PM_SYSTEM_LEVEL "2" in case of System level (Not tested)
	 */
	if (a0 == PM_CLUSTER_LEVEL)
		retstatus = pm_change_state(PM_OP_RESUME,
					PM_HINT_CONTEXT_STATE);

	/* Returned value to the ATF.
	 * If it is not 0, the system will panic
	 */
	return retstatus;
}

/**
 * @brief   Handler for cpu suspend
 *
 * @param[in] a0   Max power level to power down
 * @param[in] a1   Unusued
 *
 * @retval TEE_SUCCESS         Success
 * @retval TEE_ERROR_GENERIC   Generic error
 */
unsigned long thread_cpu_suspend_handler(unsigned long a0,
						unsigned long a1 __unused)
{
	TEE_Result retstatus = TEE_SUCCESS;

	/* a0 is the highest power level which was powered down.
	 * This can be:
	 *	PM_CORE_LEVEL i.e. "0" in case of Core level
	 *	PM_CLUSTER_LEVEL i.e. "1" in case of Cluster level
	 *	PM_SYSTEM_LEVEL "2" in case of System level (Not tested)
	 */
	if (a0 == PM_CLUSTER_LEVEL)
		retstatus = pm_change_state(PM_OP_SUSPEND,
					PM_HINT_CONTEXT_STATE);

	/* Returned value to the ATF.
	 * If it is not 0, the system will panic
	 */
	return retstatus;
}
