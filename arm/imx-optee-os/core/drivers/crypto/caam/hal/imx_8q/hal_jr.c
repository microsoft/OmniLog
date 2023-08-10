// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 *
 * Brief   CAAM Job Rings Hardware Abstration Layer.
 *	   Implementation of primitives to access HW
 */
#include <caam_common.h>
#include <caam_hal_jr.h>
#include <drivers/sc/sc_api.h>
#include <tee_api_types.h>
#include <trace.h>

/* For imx8q socs this is done using SCFW API. */
enum caam_status caam_hal_jr_setowner(vaddr_t ctrl_base __unused,
				      paddr_t jr_offset __unused,
				      enum caam_jr_owner owner __unused)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	/* First initialize the SCU driver */
	ret = sc_driver_init();
	if (ret != TEE_SUCCESS) {
		EMSG("SCU driver init failed");
		return CAAM_FAILURE;
	}

	ret = sc_rm_enable_jr(CFG_JR_INDEX);
	if (ret != TEE_SUCCESS) {
		EMSG("Can't enable CAAM JR resource");
		return CAAM_FAILURE;
	} else {
		return CAAM_NO_ERROR;
	}
}

/*
 * Nothing to do. This functions is used in hal_cfg_setup_nsjobring function
 * which is not used for imx8q socs
 */
void caam_hal_jr_prepare_backup(vaddr_t ctrl_base __unused,
				paddr_t jr_offset __unused)
{
}
