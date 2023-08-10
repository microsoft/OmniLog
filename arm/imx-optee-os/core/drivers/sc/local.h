/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2016 Freescale Semiconductor, Inc.
 * Copyright 2017-2020 NXP
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include <tee_api_types.h>

#define SC_IPC_SIZE 0x10000

#define SCFW_API_VERSION_MAJOR 1
#define SCFW_API_VERSION_MINOR 16

#define SC_RPC_VERSION 1
#define SC_RPC_MAX_MSG 8

/* Macros to fill struct sc_rpc_msg data field */
#define RPC_U32(mesg, idx) ((mesg)->data.u32[(idx)])
#define RPC_U16(mesg, idx) ((mesg)->data.u16[(idx)])
#define RPC_U8(mesg, idx)  ((mesg)->data.u8[(idx)])

/* Defines for struct sc_rpc_msg svc field */
#define SC_RPC_SVC_PM	2
#define SC_RPC_SVC_RM	3
#define SC_RPC_SVC_SECO 9

/* Define for PM function calls */
#define PM_FUNC_SET_RESOURCE_POWER_MODE 3

/* Defines for RM function calls */
#define RM_FUNC_GET_PARTITION	5
#define RM_FUNC_ASSIGN_RESOURCE 8

/* Define for SECO function calls */
#define SECO_FUNC_START_RNG 22

/* Internal SCFW API error codes */
enum sc_error {
	SC_ERR_NONE = 0,    /* Success */
	SC_ERR_VERSION,	    /* Incompatible API version */
	SC_ERR_CONFIG,	    /* Configuration error */
	SC_ERR_PARM,	    /* Bad parameter */
	SC_ERR_NOACCESS,    /* Permission error (no access) */
	SC_ERR_LOCKED,	    /* Permission error (locked) */
	SC_ERR_UNAVAILABLE, /* Unavailable (out of resources) */
	SC_ERR_NOTFOUND,    /* Not found */
	SC_ERR_NOPOWER,	    /* No power */
	SC_ERR_IPC,	    /* Generic IPC error */
	SC_ERR_BUSY,	    /* Resource is currently busy/active */
	SC_ERR_FAIL,	    /* General I/O failure */
	SC_ERR_LAST,
};

/* This enum represents the RNG SECO's state */
enum sc_seco_rng_status {
	SC_SECO_RNG_STAT_UNAVAILABLE = 0, /* Unable to initialize the RNG */
	SC_SECO_RNG_STAT_INPROGRESS,	  /* Initialization is on-going */
	SC_SECO_RNG_STAT_READY,		  /* Initialized */
};

/* This enum represents resources */
enum sc_resource {
	SC_RES_CAAM_JR1 = 500,
	SC_RES_CAAM_JR2,
	SC_RES_CAAM_JR3,
	SC_RES_CAAM_JR1_OUT = 514,
	SC_RES_CAAM_JR2_OUT,
	SC_RES_CAAM_JR3_OUT,
	SC_RES_CAAM_JR0 = 519,
	SC_RES_CAAM_JR0_OUT,
};

/*
 * This enum is used to declare a power mode. Note resources only use
 * SC_PM_PW_MODE_OFF and SC_PM_PW_MODE_ON. The other modes are used only
 * as system power modes.
 */
enum sc_power_mode {
	SC_PM_PW_MODE_OFF = 0, /* Power off */
	SC_PM_PW_MODE_STBY,    /* Power in standby */
	SC_PM_PW_MODE_LP,      /* Power in low-power */
	SC_PM_PW_MODE_ON,      /* Power on */
};

/* RPC message header */
struct sc_rpc_msg_header {
	uint8_t version; /* SC rpc version */
	uint8_t size;	 /* Size of the message */
	uint8_t svc;	 /* Type of service (RM, PM, ...)*/
	uint8_t func;	 /* Function ID or Error code */
};

/* This struct is used to send message through MU */
struct sc_rpc_msg {
	struct sc_rpc_msg_header header;
	union {
		uint32_t u32[SC_RPC_MAX_MSG - 1];
		uint16_t u16[(SC_RPC_MAX_MSG - 1) * 2];
		uint8_t u8[(SC_RPC_MAX_MSG - 1) * 4];
	} data;
};

/*
 * Send an RPC message over the secure world IPC channel. It is called by
 * client-side SCFW API
 *
 * @msg         [in/out] Message to send - Received message if a response is
 *                       expected
 * @wait_resp   Response flag
 */
TEE_Result sc_call_rpc(struct sc_rpc_msg *msg, bool wait_resp);

/*
 * This function sets the power mode of a resource.
 *
 * @resource   ID of the resource
 * @mode       Power mode to apply
 */
TEE_Result sc_pm_set_resource_power_mode(enum sc_resource resource,
					 enum sc_power_mode mode);

/*
 * This function assigns ownership of a resource to the secure partition.
 *
 * @resource   Resource to assign
 */
TEE_Result sc_rm_assign_resource(enum sc_resource resource);

#endif /* __LOCAL_H__ */
