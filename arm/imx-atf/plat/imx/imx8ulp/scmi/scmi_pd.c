/*
 * Copyright 2021 NXP
 *
 * Peng Fan <peng.fan@nxp.com>
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <scmi.h>
#include <stdlib.h>
#include <inttypes.h>
#include <stdint.h>
#include <string.h>
#include <common/debug.h>
#include <drivers/scmi.h>
#include <lib/utils_def.h>
#include <lib/libc/errno.h>
#include <upower_soc_defs.h>
#include <upower_api.h>

#define POWER_STATE_ON	(0 << 30)
#define POWER_STATE_OFF	(1 << 30)

extern int upower_pwm(int domain_id, int power_state);

enum {
	PS0 = 0,
	PS1 = 1,
	PS2 = 2,
	PS3 = 3,
	PS4 = 4,
	PS5 = 5,
	PS6 = 6,
	PS7 = 7,
	PS8 = 8,
	PS9 = 9,
	PS10 = 10,
	PS11 = 11,
	PS12 = 12,
	PS13 = 13,
	PS14 = 14,
	PS15 = 15,
	PS16 = 16,
	PS17 = 17,
	PS18 = 18,
	PS19 = 19,
};

#define SRAM_DMA1		BIT(6)
#define SRAM_FLEXSPI2		BIT(7)
#define SRAM_USB0		BIT(10)
#define SRAM_USDHC0		BIT(11)
#define SRAM_USDHC1		BIT(12)
#define SRAM_USDHC2_USB1	BIT(13)
#define SRAM_DCNANO		GENMASK_32(18, 17)
#define SRAM_EPDC		GENMASK_32(20, 19)
#define SRAM_DMA2		BIT(21)
#define SRAM_GPU2D		GENMASK_32(23, 22)
#define SRAM_GPU3D		GENMASK_32(25, 24)
#define SRAM_HIFI4		BIT(26)
#define SRAM_ISI_BUFFER		BIT(27)
#define SRAM_MIPI_CSI_FIFO	BIT(28)
#define SRAM_MIPI_DSI_FIFO	BIT(29)
#define SRAM_PXP		BIT(30)

#define SRAM_DMA0		BIT_64(33)
#define SRAM_FLEXCAN		BIT_64(34)
#define SRAM_FLEXSPI0		BIT_64(35)
#define SRAM_FLEXSPI1		BIT_64(36)

struct psw {
	char *name;
	uint32_t reg;
	int power_state;
	uint32_t count;
	int flags;
};

#define ALWAYS_ON BIT(0)

static struct psw imx8ulp_psw[] = {
	[PS6] = { .name = "PS6", .reg = PS6, .flags = ALWAYS_ON, .power_state = POWER_STATE_ON },
	[PS7] = { .name = "PS7", .reg = PS7, .power_state = POWER_STATE_OFF },
	[PS8] = { .name = "PS8", .reg = PS8, .power_state = POWER_STATE_OFF },
	[PS13] = { .name = "PS13", .reg = PS13, .power_state = POWER_STATE_OFF },
	[PS14] = { .name = "PS14", .reg = PS14, .flags = ALWAYS_ON, .power_state = POWER_STATE_OFF },
	[PS15] = { .name = "PS15", .reg = PS15, .power_state = POWER_STATE_OFF },
	[PS16] = { .name = "PS16", .reg = PS16, .flags = ALWAYS_ON, .power_state = POWER_STATE_ON },
};

struct power_domain {
	char *name;
	uint32_t reg;
	uint32_t psw_parent;
	uint32_t sram_parent;
	uint64_t bits;
	uint32_t power_state;
	bool lpav; /* belong to lpav domain */
};

/* The Rich OS need flow the macro */
#define IMX8ULP_PD_DMA1		0
#define IMX8ULP_PD_FLEXSPI2	1
#define IMX8ULP_PD_USB0		2
#define IMX8ULP_PD_USDHC0	3
#define IMX8ULP_PD_USDHC1	4
#define IMX8ULP_PD_USDHC2_USB1	5
#define IMX8ULP_PD_DCNANO	6
#define IMX8ULP_PD_EPDC		7
#define IMX8ULP_PD_DMA2		8
#define IMX8ULP_PD_GPU2D	9
#define IMX8ULP_PD_GPU3D	10
#define IMX8ULP_PD_HIFI4	11
#define IMX8ULP_PD_ISI		12
#define IMX8ULP_PD_MIPI_CSI	13
#define IMX8ULP_PD_MIPI_DSI	14
#define IMX8ULP_PD_PXP		15

#define IMX8ULP_PD_PS6		16
#define IMX8ULP_PD_PS7		17
#define IMX8ULP_PD_PS8		18
#define IMX8ULP_PD_PS13		19
#define IMX8ULP_PD_PS14		20
#define IMX8ULP_PD_PS15		21
#define IMX8ULP_PD_PS16		22
#define IMX8ULP_PD_MAX		23

static struct power_domain scmi_power_domains[] = {
	{
		.name = "DMA1",
		.reg = IMX8ULP_PD_DMA1,
		.psw_parent = PS6,
		.sram_parent = PS6,
		.bits = SRAM_DMA1,
		.power_state = POWER_STATE_OFF,
		.lpav = false,
	},
	{
		.name = "FLEXSPI2",
		.reg = IMX8ULP_PD_FLEXSPI2,
		.psw_parent = PS6,
		.sram_parent = PS6,
		.bits = SRAM_FLEXSPI2,
		.power_state = POWER_STATE_OFF,
		.lpav = false,
	},
	{
		.name = "USB0",
		.reg = IMX8ULP_PD_USB0,
		.psw_parent = PS6,
		.sram_parent = PS6,
		.bits = SRAM_USB0,
		.power_state = POWER_STATE_OFF,
		.lpav = false,
	},
	{
		.name = "USDHC0",
		.reg = IMX8ULP_PD_USDHC0,
		.psw_parent = PS6,
		.sram_parent = PS6,
		.bits = SRAM_USDHC0,
		.power_state = POWER_STATE_OFF,
		.lpav = false,
	},
	{
		.name = "USDHC1",
		.reg = IMX8ULP_PD_USDHC1,
		.psw_parent = PS6,
		.sram_parent = PS6,
		.bits = SRAM_USDHC1,
		.power_state = POWER_STATE_OFF,
		.lpav = false,
	},
	{
		.name = "USDHC2_USB1",
		.reg = IMX8ULP_PD_USDHC2_USB1,
		.psw_parent = PS6,
		.sram_parent = PS6,
		.bits = SRAM_USDHC2_USB1,
		.power_state = POWER_STATE_OFF,
		.lpav = false,
	},
	{
		.name = "DCNano",
		.reg = IMX8ULP_PD_DCNANO,
		.psw_parent = PS16,
		.sram_parent = PS16,
		.bits = SRAM_DCNANO,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "EPDC",
		.reg = IMX8ULP_PD_EPDC,
		.psw_parent = PS13,
		.sram_parent = PS13,
		.bits = SRAM_EPDC,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "DMA2",
		.reg = IMX8ULP_PD_DMA2,
		.psw_parent = PS16,
		.sram_parent = PS16,
		.bits = SRAM_DMA2,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "GPU2D",
		.reg = IMX8ULP_PD_GPU2D,
		.psw_parent = PS16,
		.sram_parent = PS16,
		.bits = SRAM_GPU2D,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "GPU3D",
		.reg = IMX8ULP_PD_GPU3D,
		.psw_parent = PS7,
		.sram_parent = PS7,
		.bits = SRAM_GPU3D,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "HIFI4",
		.reg = IMX8ULP_PD_HIFI4,
		.psw_parent = PS8,
		.sram_parent = PS8,
		.bits = SRAM_HIFI4,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "ISI",
		.reg = IMX8ULP_PD_ISI,
		.psw_parent = PS16,
		.sram_parent = PS16,
		.bits = SRAM_ISI_BUFFER,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "MIPI_CSI",
		.reg = IMX8ULP_PD_MIPI_CSI,
		.psw_parent = PS15,
		.sram_parent = PS16,
		.bits = SRAM_MIPI_CSI_FIFO,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "MIPI_DSI",
		.reg = IMX8ULP_PD_MIPI_DSI,
		.psw_parent = PS14,
		.sram_parent = PS16,
		.bits = SRAM_MIPI_DSI_FIFO,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
	{
		.name = "PXP",
		.reg = IMX8ULP_PD_PXP,
		.psw_parent = PS13,
		.sram_parent = PS13,
		.bits = SRAM_PXP,
		.power_state = POWER_STATE_OFF,
		.lpav = true,
	},
};

size_t plat_scmi_pd_count(unsigned int agent_id __unused)
{
	return ARRAY_SIZE(scmi_power_domains);
}

const char *plat_scmi_pd_get_name(unsigned int agent_id __unused,
				  unsigned int pd_id)
{
	if (pd_id >= IMX8ULP_PD_PS6)
		return imx8ulp_psw[pd_id - IMX8ULP_PD_PS6].name;

	return scmi_power_domains[pd_id].name;
}

unsigned int plat_scmi_pd_get_state(unsigned int agent_id __unused,
				    unsigned int pd_id __unused)
{
	if (pd_id >= IMX8ULP_PD_PS6)
		return imx8ulp_psw[pd_id - IMX8ULP_PD_PS6].power_state;
	return scmi_power_domains[pd_id].power_state;
}

extern void upower_wait_resp();
int upwr_pwm_power(const uint32_t swton[], const uint32_t memon[], bool on)
{
	int ret_val;
	int ret;

	if (on)
		ret = upwr_pwm_power_on(swton, memon, NULL);
	else
		ret = upwr_pwm_power_off(swton, memon, NULL);

	if (ret) {
		NOTICE("%s failed: ret: %d, state: %x\n", __func__, ret, on);
		return ret;
	}

	upower_wait_resp();

	ret = upwr_poll_req_status(UPWR_SG_PWRMGMT, NULL, NULL, &ret_val, 1000);
	if (ret != UPWR_REQ_OK) {
		NOTICE("Faliure %d, %s\n", ret, __func__);
		if (ret == UPWR_REQ_BUSY)
			return -EBUSY;
		else
			return -EINVAL;
	}

	return 0;
}

int32_t plat_scmi_pd_psw(unsigned int index, unsigned int state)
{
	uint32_t psw_parent = scmi_power_domains[index].psw_parent;
	uint32_t sram_parent = scmi_power_domains[index].sram_parent;
	uint64_t swt;
	bool on;
	int ret = 0;

	INFO("%s: index: %u psw: %u sram: %u count: %d %d state: %x\n", __func__, index, psw_parent, sram_parent, imx8ulp_psw[psw_parent].count, imx8ulp_psw[sram_parent].count, state);
	if ((imx8ulp_psw[psw_parent].flags & ALWAYS_ON) && (imx8ulp_psw[sram_parent].flags & ALWAYS_ON))
		return 0;

	on = (state == POWER_STATE_ON ? true : false);

	if (!(imx8ulp_psw[psw_parent].flags & ALWAYS_ON)) {
		swt = 1 << imx8ulp_psw[psw_parent].reg;
		if (!imx8ulp_psw[psw_parent].count) {
			if (!on) {
				NOTICE("off PSW[%d] that alreay in off state\n", psw_parent);
				ret = -EACCES;
			} else {
				ret = upwr_pwm_power((const uint32_t *)&swt, NULL, on);
				imx8ulp_psw[psw_parent].count++;
			}
		} else {
			if (on)
				imx8ulp_psw[psw_parent].count++;
			else
				imx8ulp_psw[psw_parent].count--;
			if (!imx8ulp_psw[psw_parent].count)
				ret = upwr_pwm_power((const uint32_t *)&swt, NULL, on);
		}
	}

	if (!(imx8ulp_psw[sram_parent].flags & ALWAYS_ON) && (psw_parent != sram_parent)) {
		swt = 1 << imx8ulp_psw[sram_parent].reg;
		if (!imx8ulp_psw[sram_parent].count) {
			if (!on) {
				NOTICE("off PSW[%d] that alreay in off state\n", sram_parent);
				ret = -EACCES;
			} else {
				ret = upwr_pwm_power((const uint32_t *)&swt, NULL, on);
				imx8ulp_psw[sram_parent].count++;
			}
		} else {
			if (on)
				imx8ulp_psw[sram_parent].count++;
			else
				imx8ulp_psw[sram_parent].count--;
			if (!imx8ulp_psw[sram_parent].count)
				ret = upwr_pwm_power((const uint32_t *)&swt, NULL, on);
		}
	}

	INFO("Done %s: index: %u psw: %u sram: %u count: %d %d state: %x\n", __func__, index, psw_parent, sram_parent, imx8ulp_psw[psw_parent].count, imx8ulp_psw[sram_parent].count, state);
	return ret;
}

extern bool is_lpav_owned_by_apd(void);
bool pd_allow_power_off(unsigned int pd_id)
{
	if (scmi_power_domains[pd_id].lpav) {
		if (!is_lpav_owned_by_apd())
			return false;
	}

	return true;
}

int32_t plat_scmi_pd_set_state(unsigned int agent_id __unused,
			       unsigned int flags,
			       unsigned int pd_id,
			       unsigned int state)
{
	uint64_t mem;
	bool on;
	int i, ret;

	INFO("%s: agend_id: %d flags: 0x%x: pd_id: %d, state: 0x%x\n", __func__, agent_id, flags, pd_id, state);
	if (flags != 0 || pd_id >= IMX8ULP_PD_PS6)
		return SCMI_NOT_SUPPORTED;

	for (i = 0; i < IMX8ULP_PD_PS6; i++) {
		if (scmi_power_domains[i].reg != pd_id)
			continue;

		break;
	}

	if (i == IMX8ULP_PD_PS6)
		return SCMI_NOT_FOUND;

	if (state == scmi_power_domains[i].power_state)
		return SCMI_SUCCESS;

	mem = scmi_power_domains[i].bits;
	on = (state == POWER_STATE_ON ? true : false);
	if (on) {
		ret = plat_scmi_pd_psw(i, state);
		if (ret)
			return SCMI_DENIED;

		ret = upwr_pwm_power(NULL, (const uint32_t *)&mem, on);
		if (ret)
			return SCMI_DENIED;
	} else {
		if (!pd_allow_power_off(i))
			return SCMI_DENIED;

		ret = upwr_pwm_power(NULL, (const uint32_t *)&mem, on);
		if (ret)
			return SCMI_DENIED;

		ret = plat_scmi_pd_psw(i, state);
		if (ret)
			return SCMI_DENIED;
	}
	INFO("Done mem %" PRIx64 " %s\n", mem, on ? "on" : "off");

	scmi_power_domains[pd_id].power_state = state;

	return SCMI_SUCCESS;
}
