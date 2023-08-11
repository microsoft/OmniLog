// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2020 NXP
 */
#include <drivers/sc/sc_api.h>
#include <tee_api_types.h>
#include <trace.h>

#include "local.h"

/* RNG instantiation timeout (number of loop) */
#define RNG_TIMEOUT 100

TEE_Result sc_rm_enable_jr(unsigned int jr_index)
{
	TEE_Result error = TEE_ERROR_GENERIC;
	enum sc_resource jr_res = 0;
	enum sc_resource jr_out_res = 0;

	switch (jr_index) {
	case 0:
		jr_res = SC_RES_CAAM_JR0;
		jr_out_res = SC_RES_CAAM_JR0_OUT;
		break;

	case 1:
		jr_res = SC_RES_CAAM_JR1;
		jr_out_res = SC_RES_CAAM_JR1_OUT;
		break;

	case 2:
		jr_res = SC_RES_CAAM_JR2;
		jr_out_res = SC_RES_CAAM_JR2_OUT;
		break;

	case 3:
		jr_res = SC_RES_CAAM_JR3;
		jr_out_res = SC_RES_CAAM_JR3_OUT;
		break;

	default:
		EMSG("JR Index badly defined, should be 0, 1, 2 or 3");
		return error;
	}

	/* Assign JR resources to secure world */
	error = sc_rm_assign_resource(jr_res);
	if (error != TEE_SUCCESS) {
		EMSG("Assign SC_R_CAAM_JR%" PRId32 "resource failed", jr_index);
		return error;
	}

	error = sc_rm_assign_resource(jr_out_res);
	if (error != TEE_SUCCESS) {
		EMSG("Assign SC_R_CAAM_JR%" PRId32 "_OUT resource failed",
		     jr_index);
		return error;
	}

	/* Power ON JR resources */
	error = sc_pm_set_resource_power_mode(jr_res, SC_PM_PW_MODE_ON);
	if (error != TEE_SUCCESS) {
		EMSG("POWER ON SC_R_CAAM_JR%" PRId32 "resource failed",
		     jr_index);
		return error;
	}

	error = sc_pm_set_resource_power_mode(jr_out_res, SC_PM_PW_MODE_ON);
	if (error != TEE_SUCCESS) {
		EMSG("POWER ON SC_R_CAAM_JR%" PRId32 "_OUT resource failed",
		     jr_index);
		return error;
	}

	return error;
}

TEE_Result sc_seco_start_rng(void)
{
	struct sc_rpc_msg msg = {};
	TEE_Result error = TEE_ERROR_GENERIC;
	enum sc_error scu_error = SC_ERR_LAST;
	enum sc_seco_rng_status status = SC_SECO_RNG_STAT_UNAVAILABLE;
	int timeout = RNG_TIMEOUT;

	for (; timeout; timeout--) {
		msg.header.version = SC_RPC_VERSION;
		msg.header.size = 1;
		msg.header.svc = SC_RPC_SVC_SECO;
		msg.header.func = SECO_FUNC_START_RNG;

		error = sc_call_rpc(&msg, true);
		if (error != TEE_SUCCESS) {
			EMSG("Configuration error");
			return error;
		}

		scu_error = msg.header.func;
		if (scu_error != SC_ERR_NONE) {
			EMSG("Unable to start RNG or get RNG status");
			EMSG("sc_error code is: %" PRId32, scu_error);
			return TEE_ERROR_GENERIC;
		}

		status = (enum sc_seco_rng_status)RPC_U32(&msg, 0);

		if (status == SC_SECO_RNG_STAT_READY) {
			return TEE_SUCCESS;
		} else if (status == SC_SECO_RNG_STAT_INPROGRESS) {
			DMSG("RNG initialization is on-going");
		} else {
			if (status == SC_SECO_RNG_STAT_UNAVAILABLE)
				EMSG("Unable to initialize the RNG");
			else
				EMSG("RNG state is not defined");

			return TEE_ERROR_GENERIC;
		}
	}

	EMSG("RNG initialization is still on-going after timeout");
	return TEE_ERROR_GENERIC;
}
