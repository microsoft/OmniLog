// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2020 NXP
 *
 * Brief   CAAM Configuration.
 */
#include <caam_hal_cfg.h>

/*
 * Non-secure job ring configuration is done by boot software and could not
 * be changed.
 */
void caam_hal_cfg_setup_nsjobring(struct caam_jrcfg *jrcfg __unused)
{
}
