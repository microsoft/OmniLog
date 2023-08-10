// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 *
 * Brief   CAAM Controller Hardware Abstration Layer.\n
 *	   Implementation of primitives to access HW
 */
#include <caam_hal_ctrl.h>
#include <compiler.h>

/* Nothing to do, can't access to MCFGR register (Only accessible by SECO) */
void caam_hal_ctrl_init(vaddr_t baseaddr __unused)
{
}
