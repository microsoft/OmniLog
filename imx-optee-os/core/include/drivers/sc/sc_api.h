/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2020 NXP
 */
#ifndef __SC_API_H__
#define __SC_API_H__

#include <tee_api_types.h>

/*
 * This function initializes the secure os IPC/MU and the following global
 * variables: ipc_secure and secure_partition.
 * When CFG_IMX_SC_EXTERN_INIT is set this function has to be
 * called before the CAAM initialization. It's then export and used by CAAM init
 * function.
 */
#ifdef CFG_IMX_SC_EXTERN_INIT
TEE_Result sc_driver_init(void);
#endif

/*
 * This function enable a CAAM Job Ring for the secure world.
 * It's done in two steps:
 *  - Assign CAAM JR resources to secure world
 *  - Power ON CAAM JR resources
 *
 * @jr_index   Index of the CAAM Job Ring to enable
 */
TEE_Result sc_rm_enable_jr(unsigned int jr_index);

/*
 * This function starts the random number generator and returns the RNG status.
 * Note that the RNG is started automatically after all CPUs are booted. This
 * function can then be used to start the RNG earlier or to check the status.
 */
TEE_Result sc_seco_start_rng(void);

#endif /* __SC_API_H__ */
