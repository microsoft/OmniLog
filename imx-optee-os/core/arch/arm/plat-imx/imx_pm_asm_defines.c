// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2018, Linaro Limited
 * Copyright 2018 NXP
 */

#include <gen-asm-defines.h>
#include "imx_pm.h"

DEFINES
{
	/* Definition of the Assembly function arguments */
	DEFINE(PM_ASM_ARG_PA_ADDR_OFF,
	       offsetof(struct imx_pm_asm_arg, pa_addr));
	DEFINE(PM_ASM_ARG_PM_INFO_OFF,
	       offsetof(struct imx_pm_asm_arg, pm_info));

	/* Definition of the MX7 PM info structure offset */
	DEFINE(PM_INFO_MX7_M4_RESERVE0_OFF,
	       offsetof(struct imx7_pm_info, m4_reserve0));
	DEFINE(PM_INFO_MX7_M4_RESERVE1_OFF,
	       offsetof(struct imx7_pm_info, m4_reserve1));
	DEFINE(PM_INFO_MX7_M4_RESERVE2_OFF,
	       offsetof(struct imx7_pm_info, m4_reserve2));
	DEFINE(PM_INFO_MX7_VBASE_OFF, offsetof(struct imx7_pm_info, va_base));
	DEFINE(PM_INFO_MX7_PBASE_OFF, offsetof(struct imx7_pm_info, pa_base));
	DEFINE(PM_INFO_MX7_ENTRY_OFF, offsetof(struct imx7_pm_info, entry));
	DEFINE(PM_INFO_MX7_RESUME_ADDR_OFF,
	       offsetof(struct imx7_pm_info, tee_resume));
	DEFINE(PM_INFO_MX7_DDR_TYPE_OFF,
	       offsetof(struct imx7_pm_info, ddr_type));
	DEFINE(PM_INFO_MX7_SIZE_OFF,
	       offsetof(struct imx7_pm_info, pm_info_size));
	DEFINE(PM_INFO_MX7_DDRC_P_OFF,
	       offsetof(struct imx7_pm_info, ddrc_pa_base));
	DEFINE(PM_INFO_MX7_DDRC_V_OFF,
	       offsetof(struct imx7_pm_info, ddrc_va_base));
	DEFINE(PM_INFO_MX7_DDRC_PHY_P_OFF,
	       offsetof(struct imx7_pm_info, ddrc_phy_pa_base));
	DEFINE(PM_INFO_MX7_DDRC_PHY_V_OFF,
	       offsetof(struct imx7_pm_info, ddrc_phy_va_base));
	DEFINE(PM_INFO_MX7_SRC_P_OFF,
	       offsetof(struct imx7_pm_info, src_pa_base));
	DEFINE(PM_INFO_MX7_SRC_V_OFF,
	       offsetof(struct imx7_pm_info, src_va_base));
	DEFINE(PM_INFO_MX7_IOMUXC_GPR_P_OFF,
	       offsetof(struct imx7_pm_info, iomuxc_gpr_pa_base));
	DEFINE(PM_INFO_MX7_IOMUXC_GPR_V_OFF,
	       offsetof(struct imx7_pm_info, iomuxc_gpr_va_base));
	DEFINE(PM_INFO_MX7_CCM_P_OFF,
	       offsetof(struct imx7_pm_info, ccm_pa_base));
	DEFINE(PM_INFO_MX7_CCM_V_OFF,
	       offsetof(struct imx7_pm_info, ccm_va_base));
	DEFINE(PM_INFO_MX7_GPC_P_OFF,
	       offsetof(struct imx7_pm_info, gpc_pa_base));
	DEFINE(PM_INFO_MX7_GPC_V_OFF,
	       offsetof(struct imx7_pm_info, gpc_va_base));
	DEFINE(PM_INFO_MX7_SNVS_P_OFF,
	       offsetof(struct imx7_pm_info, snvs_pa_base));
	DEFINE(PM_INFO_MX7_SNVS_V_OFF,
	       offsetof(struct imx7_pm_info, snvs_va_base));
	DEFINE(PM_INFO_MX7_ANATOP_P_OFF,
	       offsetof(struct imx7_pm_info, anatop_pa_base));
	DEFINE(PM_INFO_MX7_ANATOP_V_OFF,
	       offsetof(struct imx7_pm_info, anatop_va_base));
	DEFINE(PM_INFO_MX7_LPSR_P_OFF,
	       offsetof(struct imx7_pm_info, lpsr_pa_base));
	DEFINE(PM_INFO_MX7_LPSR_V_OFF,
	       offsetof(struct imx7_pm_info, lpsr_va_base));
	DEFINE(PM_INFO_MX7_GIC_DIST_P_OFF,
	       offsetof(struct imx7_pm_info, gic_pa_base));
	DEFINE(PM_INFO_MX7_GIC_DIST_V_OFF,
	       offsetof(struct imx7_pm_info, gic_va_base));
	DEFINE(PM_INFO_MX7_TTBR0_OFF, offsetof(struct imx7_pm_info, ttbr0));
	DEFINE(PM_INFO_MX7_TTBR1_OFF, offsetof(struct imx7_pm_info, ttbr1));
	DEFINE(PM_INFO_MX7_NUM_ONLINE_CPUS_OFF,
	       offsetof(struct imx7_pm_info, num_online_cpus));
	DEFINE(PM_INFO_MX7_NUM_LPI_CPUS_OFF,
	       offsetof(struct imx7_pm_info, num_lpi_cpus));
	DEFINE(PM_INFO_MX7_VAL_OFF, offsetof(struct imx7_pm_info, val));
	DEFINE(PM_INFO_MX7_FLAG0_OFF, offsetof(struct imx7_pm_info, flag0));
	DEFINE(PM_INFO_MX7_FLAG1_OFF, offsetof(struct imx7_pm_info, flag1));
	DEFINE(PM_INFO_MX7_DDRC_REG_NUM_OFF,
	       offsetof(struct imx7_pm_info, ddrc_num));
	DEFINE(PM_INFO_MX7_DDRC_REG_OFF,
	       offsetof(struct imx7_pm_info, ddrc_val));
	DEFINE(PM_INFO_MX7_DDRC_PHY_REG_NUM_OFF,
	       offsetof(struct imx7_pm_info, ddrc_phy_num));
	DEFINE(PM_INFO_MX7_DDRC_PHY_REG_OFF,
	       offsetof(struct imx7_pm_info, ddrc_phy_val));

	DEFINE(PM_INFO_PBASE_OFF,
	       offsetof(struct imx6_pm_info, pa_base));
	DEFINE(PM_INFO_TEE_RESUME_OFF,
	       offsetof(struct imx6_pm_info, tee_resume));
	DEFINE(PM_INFO_DDR_TYPE_OFF,
	       offsetof(struct imx6_pm_info, ddr_type));
	DEFINE(PM_INFO_INFO_SIZE_OFF,
	       offsetof(struct imx6_pm_info, pm_info_size));
	DEFINE(PM_INFO_MMDC0_P_OFF,
	       offsetof(struct imx6_pm_info, mmdc0_pa_base));
	DEFINE(PM_INFO_MMDC0_V_OFF,
	       offsetof(struct imx6_pm_info, mmdc0_va_base));
	DEFINE(PM_INFO_MMDC1_P_OFF,
	       offsetof(struct imx6_pm_info, mmdc1_pa_base));
	DEFINE(PM_INFO_MMDC1_V_OFF,
	       offsetof(struct imx6_pm_info, mmdc1_va_base));
	DEFINE(PM_INFO_SRC_P_OFF,
	       offsetof(struct imx6_pm_info, src_pa_base));
	DEFINE(PM_INFO_SRC_V_OFF,
	       offsetof(struct imx6_pm_info, src_va_base));
	DEFINE(PM_INFO_IOMUXC_P_OFF,
	       offsetof(struct imx6_pm_info, iomuxc_pa_base));
	DEFINE(PM_INFO_IOMUXC_V_OFF,
	       offsetof(struct imx6_pm_info, iomuxc_va_base));
	DEFINE(PM_INFO_CCM_P_OFF,
	       offsetof(struct imx6_pm_info, ccm_pa_base));
	DEFINE(PM_INFO_CCM_V_OFF,
	       offsetof(struct imx6_pm_info, ccm_va_base));
	DEFINE(PM_INFO_GPC_P_OFF,
	       offsetof(struct imx6_pm_info, gpc_pa_base));
	DEFINE(PM_INFO_GPC_V_OFF,
	       offsetof(struct imx6_pm_info, gpc_va_base));
	DEFINE(PM_INFO_PL310_V_OFF,
	       offsetof(struct imx6_pm_info, pl310_va_base));
	DEFINE(PM_INFO_ANATOP_P_OFF,
	       offsetof(struct imx6_pm_info, anatop_pa_base));
	DEFINE(PM_INFO_ANATOP_V_OFF,
	       offsetof(struct imx6_pm_info, anatop_va_base));
	DEFINE(PM_INFO_SEMA4_P_OFF,
	       offsetof(struct imx6_pm_info, sema4_pa_base));
	DEFINE(PM_INFO_SEMA4_V_OFF,
	       offsetof(struct imx6_pm_info, sema4_va_base));
	DEFINE(PM_INFO_TTBR0_OFF,
	       offsetof(struct imx6_pm_info, ttbr0));
	DEFINE(PM_INFO_TTBR1_OFF,
	       offsetof(struct imx6_pm_info, ttbr1));
	DEFINE(PM_INFO_SAVED_DIAGNOSTIC_OFF,
	       offsetof(struct imx6_pm_info, diagnostic));
	DEFINE(PM_INFO_IDLE_STATE,
	       offsetof(struct imx6_pm_info, idle_state));
	DEFINE(PM_INFO_MMDC_IO_NUM_OFF,
	       offsetof(struct imx6_pm_info, mmdc_io_num));
	DEFINE(PM_INFO_MMDC_IO_VAL_OFF,
	       offsetof(struct imx6_pm_info, mmdc_io_val));
/* below offsets depends on MX6_MAX_MMDC_IO_NUM(36) definition */
	DEFINE(PM_INFO_MMDC_NUM_OFF,
	       offsetof(struct imx6_pm_info, mmdc_num));
	DEFINE(PM_INFO_MMDC_VAL_OFF,
	       offsetof(struct imx6_pm_info, mmdc_val));

	DEFINE(PM_INFO_MX7ULP_M4_RESERVE0_OFF,
	       offsetof(struct imx7ulp_pm_info, m4_reserve0));
	DEFINE(PM_INFO_MX7ULP_M4_RESERVE1_OFF,
	       offsetof(struct imx7ulp_pm_info, m4_reserve1));
	DEFINE(PM_INFO_MX7ULP_M4_RESERVE2_OFF,
	       offsetof(struct imx7ulp_pm_info, m4_reserve2));
	DEFINE(PM_INFO_MX7ULP_PBASE_OFF,
	       offsetof(struct imx7ulp_pm_info, pbase));
	DEFINE(PM_INFO_MX7ULP_RESUME_ADDR_OFF,
	       offsetof(struct imx7ulp_pm_info, resume_addr));
	DEFINE(PM_INFO_MX7ULP_SIZE_OFF,
	       offsetof(struct imx7ulp_pm_info, pm_info_size));
	DEFINE(PM_INFO_MX7ULP_SIM_VBASE_OFF,
	       offsetof(struct imx7ulp_pm_info, sim_base));
	DEFINE(PM_INFO_MX7ULP_SCG1_VBASE_OFF,
	       offsetof(struct imx7ulp_pm_info, scg1_base));
	DEFINE(PM_INFO_MX7ULP_MMDC_VBASE_OFF,
	       offsetof(struct imx7ulp_pm_info, mmdc_base));
	DEFINE(PM_INFO_MX7ULP_MMDC_IO_VBASE_OFF,
	       offsetof(struct imx7ulp_pm_info, mmdc_io_base));
	DEFINE(PM_INFO_MX7ULP_SMC1_VBASE_OFF,
	       offsetof(struct imx7ulp_pm_info, smc1_base));
	DEFINE(PM_INFO_MX7ULP_SCG1_VAL_OFF,
	       offsetof(struct imx7ulp_pm_info, scg1));
	DEFINE(PM_INFO_MX7ULP_TTBR0_V_OFF,
	       offsetof(struct imx7ulp_pm_info, ttbr0));
	DEFINE(PM_INFO_MX7ULP_TTBR1_V_OFF,
	       offsetof(struct imx7ulp_pm_info, ttbr1));
	DEFINE(PM_INFO_MX7ULP_GPIO_REG_OFF,
	       offsetof(struct imx7ulp_pm_info, gpio));
	DEFINE(PM_INFO_MX7ULP_IOMUX_NUM_OFF,
	       offsetof(struct imx7ulp_pm_info, iomux_num));
	DEFINE(PM_INFO_MX7ULP_IOMUX_VAL_OFF,
	       offsetof(struct imx7ulp_pm_info, iomux_val));
	DEFINE(PM_INFO_MX7ULP_SELECT_INPUT_NUM_OFF,
	       offsetof(struct imx7ulp_pm_info, select_input_num));
	DEFINE(PM_INFO_MX7ULP_SELECT_INPUT_VAL_OFF,
	       offsetof(struct imx7ulp_pm_info, select_input_val));
	DEFINE(PM_INFO_MX7ULP_MMDC_IO_NUM_OFF,
	       offsetof(struct imx7ulp_pm_info, mmdc_io_num));
	DEFINE(PM_INFO_MX7ULP_MMDC_IO_VAL_OFF,
	       offsetof(struct imx7ulp_pm_info, mmdc_io_val));
/* below offsets depends on MX7ULP_MAX_MMDC_IO_NUM(36) definition */
	DEFINE(PM_INFO_MX7ULP_MMDC_NUM_OFF,
	       offsetof(struct imx7ulp_pm_info, mmdc_num));
	DEFINE(PM_INFO_MX7ULP_MMDC_VAL_OFF,
	       offsetof(struct imx7ulp_pm_info, mmdc_val));
}
