// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 *
 * Brief   CAAM Random Number Generator Hardware Abstration Layer.
 *         Implementation of primitives to access HW.
 */
#include <caam_hal_rng.h>
#include <caam_status.h>
#include <types_ext.h>

enum caam_status caam_hal_rng_instantiated(vaddr_t baseaddr)
{
	return caam_hal_common_rng_instantiated(baseaddr);
}
