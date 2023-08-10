// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2020 NXP
 */
#include <drivers/imx_mu.h>
#include <drivers/sc/sc_api.h>
#include <imx-regs.h>
#include <initcall.h>
#include <kernel/mutex.h>
#include <mm/core_memprot.h>
#include <tee_api_types.h>
#include <trace.h>

#include "local.h"

/* Mutex for scu-ap communication */
static struct mutex scu_mu_mutex = MUTEX_INITIALIZER;

/* IPC address used by secure world */
vaddr_t secure_ipc;

register_phys_mem(MEM_AREA_IO_SEC, SC_IPC_BASE_SECURE, SC_IPC_SIZE);

/*
 * Read a message from an IPC channel
 *
 * @ipc   IPC channel
 * @msg   [out] Received message pointer
 */
static TEE_Result sc_ipc_read(vaddr_t ipc, struct sc_rpc_msg *msg)
{
	unsigned int count = 0;

	if (!msg) {
		EMSG("Error, msg is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	/* Read header, i.e. first 32 bits */
	mu_receive_msg(ipc, count, (uint32_t *)msg);

	/* Check the size of the message to receive */
	if (msg->header.size > SC_RPC_MAX_MSG) {
		EMSG("Error, size of the message is > than SC_RPC_MAX_MSG");
		return TEE_ERROR_BAD_FORMAT;
	}

	for (count = 1; count < msg->header.size; count++)
		mu_receive_msg(ipc, count % MU_NB_RR,
			       &msg->data.u32[count - 1]);

	return TEE_SUCCESS;
}

/*
 * Write a message to an IPC channel
 *
 * @ipc   IPC channel
 * @msg   Send message pointer
 */
static TEE_Result sc_ipc_write(vaddr_t ipc, struct sc_rpc_msg *msg)
{
	unsigned int count = 0;

	if (!msg) {
		EMSG("Error, msg is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (msg->header.size > SC_RPC_MAX_MSG) {
		EMSG("Error, msg->size is > than SC_RPC_MAX_MSG");
		return TEE_ERROR_BAD_FORMAT;
	}

	/* Send header, i.e. first 32 bits */
	mu_send_msg(ipc, count, *(uint32_t *)msg);

	for (count = 1; count < msg->header.size; count++)
		mu_send_msg(ipc, count % MU_NB_TR, msg->data.u32[count - 1]);

	return TEE_SUCCESS;
}

/*
 * Get the partition id of secure world
 *
 * @partition   [out] Partition id
 */
static TEE_Result sc_rm_get_partition(uint8_t *partition)
{
	struct sc_rpc_msg msg = {};
	TEE_Result error = TEE_ERROR_GENERIC;
	enum sc_error scu_error = SC_ERR_LAST;

	msg.header.version = SC_RPC_VERSION;
	msg.header.size = 1;
	msg.header.svc = SC_RPC_SVC_RM;
	msg.header.func = RM_FUNC_GET_PARTITION;

	error = sc_call_rpc(&msg, true);
	if (error != TEE_SUCCESS) {
		EMSG("Communication error");
		return error;
	}

	scu_error = msg.header.func;
	if (scu_error != SC_ERR_NONE) {
		EMSG("Unable to get partition id, sc_error code is: %" PRId32,
		     scu_error);
		return TEE_ERROR_GENERIC;
	}

	*partition = RPC_U8(&msg, 0);

	return TEE_SUCCESS;
}

TEE_Result sc_call_rpc(struct sc_rpc_msg *msg, bool wait_resp)
{
	TEE_Result error = TEE_ERROR_GENERIC;

	mutex_lock(&scu_mu_mutex);

	error = sc_ipc_write(secure_ipc, msg);

	if (error == TEE_SUCCESS && wait_resp)
		error = sc_ipc_read(secure_ipc, msg);

	mutex_unlock(&scu_mu_mutex);

	return error;
}

TEE_Result sc_pm_set_resource_power_mode(enum sc_resource resource,
					 enum sc_power_mode mode)
{
	struct sc_rpc_msg msg = {};
	TEE_Result error = TEE_ERROR_GENERIC;
	enum sc_error scu_error = SC_ERR_LAST;

	msg.header.version = SC_RPC_VERSION;
	msg.header.size = 2;
	msg.header.svc = SC_RPC_SVC_PM;
	msg.header.func = PM_FUNC_SET_RESOURCE_POWER_MODE;
	RPC_U16(&msg, 0) = (uint16_t)resource;
	RPC_U8(&msg, 2) = (uint8_t)mode;

	error = sc_call_rpc(&msg, true);
	if (error != TEE_SUCCESS) {
		EMSG("Communication error");
		return error;
	}

	scu_error = msg.header.func;
	if (scu_error != SC_ERR_NONE) {
		EMSG("Unable to set resource power mode");
		EMSG("sc_error code is: %" PRId32, scu_error);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result sc_rm_assign_resource(enum sc_resource resource)
{
	struct sc_rpc_msg msg = {};
	TEE_Result error = TEE_ERROR_GENERIC;
	enum sc_error scu_error = SC_ERR_LAST;
	uint8_t secure_partition = 0;

	error = sc_rm_get_partition(&secure_partition);
	if (error != TEE_SUCCESS) {
		EMSG("Can't get secure partition id");
		return error;
	}

	msg.header.version = SC_RPC_VERSION;
	msg.header.size = 2;
	msg.header.svc = SC_RPC_SVC_RM;
	msg.header.func = RM_FUNC_ASSIGN_RESOURCE;
	RPC_U16(&msg, 0) = (uint16_t)resource;
	RPC_U8(&msg, 2) = secure_partition;

	error = sc_call_rpc(&msg, true);
	if (error != TEE_SUCCESS) {
		EMSG("Communication error");
		return error;
	}

	scu_error = msg.header.func;
	if (scu_error != SC_ERR_NONE) {
		EMSG("Unable to assign resource, sc_error code is: %" PRId32,
		     scu_error);
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

#ifdef CFG_IMX_SC_EXTERN_INIT
TEE_Result sc_driver_init(void)
#else
static TEE_Result sc_driver_init(void)
#endif
{
	vaddr_t vbase_secure = 0;

	/* Update MU virtual base address */
	vbase_secure =
		(vaddr_t)phys_to_virt(SC_IPC_BASE_SECURE, MEM_AREA_IO_SEC);
	if (!vbase_secure) {
		EMSG("MU virtual base address is NULL");
		return TEE_ERROR_BAD_STATE;
	}

	/* Init MU and update secure_id struct  */
	mutex_lock(&scu_mu_mutex);
	mu_init(vbase_secure);
	mutex_unlock(&scu_mu_mutex);

	secure_ipc = vbase_secure;

	DMSG("SC driver init done");

	return TEE_SUCCESS;
}

/*
 * TODO: Improve driver initialization
 *
 * This way of initializing the driver is a workaround to ensure the init order
 * (SCU driver has to be initialize before CAAM driver)
 */
#ifndef CFG_IMX_SC_EXTERN_INIT
driver_init(sc_driver_init);
#endif
