// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 *
 * Brief   CAAM Random Number Generator Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_rng.h>
#include <caam_status.h>
#include <drivers/sc/sc_api.h>
#include <tee_api_types.h>
#include <trace.h>

enum caam_status caam_hal_rng_instantiated(vaddr_t baseaddr __unused)
{
	TEE_Result ret = TEE_ERROR_GENERIC;

	ret = sc_seco_start_rng();
	if (ret != TEE_SUCCESS) {
		EMSG("RNG instantiation failed");
		return CAAM_FAILURE;
	} else {
		return CAAM_NO_ERROR;
	}
}
