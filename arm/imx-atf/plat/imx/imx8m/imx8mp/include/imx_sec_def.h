/*
 * Copyright 2020 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef IMX_SEC_DEF_H
#define IMX_SEC_DEF_H

/* RDC MDA index */
enum rdc_mda_idx {
	RDC_MDA_A53 = 0,
	RDC_MDA_M7 = 1,
	RDC_MDA_PCIE_CTRL1 = 2,
	RDC_MDA_SDMA3p = 3,
	RDC_MDA_SDMA3b = 4,
	RDC_MDA_LCDIF = 5,
	RDC_MDA_ISI = 6,
	RDC_MDA_NPU = 7,
	RDC_MDA_Coresight = 8,
	RDC_MDA_DAP = 9,
	RDC_MDA_CAAM = 10,
	RDC_MDA_SDMA1p = 11,
	RDC_MDA_SDMA1b = 12,
	RDC_MDA_APBHDMA = 13,
	RDC_MDA_RAWNAND = 14,
	RDC_MDA_uSDHC1 = 15,
	RDC_MDA_uSDHC2 = 16,
	RDC_MDA_uSDHC3 = 17,
	RDC_MDA_AUDIO_PROCESSOR = 18,
	RDC_MDA_USB1 = 19,
	RDC_MDA_USB2 = 20,
	RDC_MDA_TESTPORT = 21,
	RDC_MDA_ENET1_TX = 22,
	RDC_MDA_ENET1_RX = 23,
	RDC_MDA_SDMA2 = 24,
	RDC_MDA_SDMA3_to_SPBA2 = 25,
	RDC_MDA_SDMA1_to_SPBA1 = 26,
	RDC_MDA_LCDIF2 = 27,
	RDC_MDA_HDMI_TX = 28,
	RDC_MDA_ENET2 = 29,
	RDC_MDA_GPU3D = 30,
	RDC_MDA_GPU2D = 31,
	RDC_MDA_VPU_G1 = 32,
	RDC_MDA_VPU_G2 = 33,
	RDC_MDA_VPU_VC8000E = 34,
	RDC_MDA_AUDIO_EDMA = 35,
	RDC_MDA_ISP1 = 36,
	RDC_MDA_ISP2 = 37,
	RDC_MDA_DEWARP = 38,
	RDC_MDA_GIC500 = 39,
};

/* RDC Peripherals index */
enum rdc_pdap_idx {
	RDC_PDAP_GPIO1 = 0,
	RDC_PDAP_GPIO2 = 1,
	RDC_PDAP_GPIO3 = 2,
	RDC_PDAP_GPIO4 = 3,
	RDC_PDAP_GPIO5 = 4,
	RDC_PDAP_MU_2_A = 5,
	RDC_PDAP_ANA_TSENSOR = 6,
	RDC_PDAP_ANA_OSC = 7,
	RDC_PDAP_WDOG1 = 8,
	RDC_PDAP_WDOG2 = 9,
	RDC_PDAP_WDOG3 = 10,
	RDC_PDAP_GPT1 = 13,
	RDC_PDAP_GPT2 = 14,
	RDC_PDAP_GPT3 = 15,
	RDC_PDAP_MU_2_B = 16,
	RDC_PDAP_ROMCP = 17,
	RDC_PDAP_MU_3_A = 18,
	RDC_PDAP_IOMUXC = 19,
	RDC_PDAP_IOMUXC_GPR = 20,
	RDC_PDAP_OCOTP_CTRL = 21,
	RDC_PDAP_ANA_PLL = 22,
	RDC_PDAP_SNVS_HP = 23,
	RDC_PDAP_CCM = 24,
	RDC_PDAP_SRC = 25,
	RDC_PDAP_GPC = 26,
	RDC_PDAP_SEMAPHORE1 = 27,
	RDC_PDAP_SEMAPHORE2 = 28,
	RDC_PDAP_RDC = 29,
	RDC_PDAP_CSU = 30,
	RDC_PDAP_MU_3_B = 31,
	RDC_PDAP_ISI = 32,
	RDC_PDAP_ISP0 = 33,
	RDC_PDAP_ISP1 = 34,
	RDC_PDAP_IPS_Dewarp = 35,
	RDC_PDAP_MIPI_CSI0 = 36,
	RDC_PDAP_HSIOMIX_BLK_CTL = 37,
	RDC_PDAP_PWM1 = 38,
	RDC_PDAP_PWM2 = 39,
	RDC_PDAP_PWM3 = 40,
	RDC_PDAP_PWM4 = 41,
	RDC_PDAP_System_Counter_RD = 42,
	RDC_PDAP_System_Counter_CMP = 43,
	RDC_PDAP_System_Counter_CTRL = 44,
	RDC_PDAP_I2C5 = 45,
	RDC_PDAP_GPT6 = 46,
	RDC_PDAP_GPT5 = 47,
	RDC_PDAP_GPT4 = 48,
	RDC_PDAP_MIPI_CSI1 = 49,
	RDC_PDAP_MIPI_DSI0 = 50,
	RDC_PDAP_MEDIAMIX_BLK_CTL = 51,
	RDC_PDAP_LCDIF1 = 52,
	RDC_PDAP_eDMA_Management_Page = 53,
	RDC_PDAP_eDMA_Channels_15_0 = 54,
	RDC_PDAP_eDMA_Channels_31_16 = 55,
	RDC_PDAP_TZASC = 56,
	RDC_PDAP_I2C6 = 57,
	RDC_PDAP_CAAM = 58,
	RDC_PDAP_LCDIF2 = 59,
	RDC_PDAP_PERFMON1 = 60,
	RDC_PDAP_PERFMON2 = 61,
	RDC_PDAP_NOC_BLK_CTL = 62,
	RDC_PDAP_QoSC = 63,
	RDC_PDAP_LVDS0 = 64,
	RDC_PDAP_LVDS1 = 65,
	RDC_PDAP_I2C1 = 66,
	RDC_PDAP_I2C2 = 67,
	RDC_PDAP_I2C3 = 68,
	RDC_PDAP_I2C4 = 69,
	RDC_PDAP_UART4 = 70,
	RDC_PDAP_HDMI_TX = 71,
	RDC_PDAP_IRQ_STEER_Audio_Processor = 72,
	RDC_PDAP_SDMA2 = 73,
	RDC_PDAP_MU_1_A = 74,
	RDC_PDAP_MU_1_B = 75,
	RDC_PDAP_SEMAPHORE_HS = 76,
	RDC_PDAP_SAI1 = 78,
	RDC_PDAP_SAI2 = 79,
	RDC_PDAP_SAI3 = 80,
	RDC_PDAP_CAN_FD1 = 81,
	RDC_PDAP_SAI5 = 82,
	RDC_PDAP_SAI6 = 83,
	RDC_PDAP_uSDHC1 = 84,
	RDC_PDAP_uSDHC2 = 85,
	RDC_PDAP_uSDHC3 = 86,
	RDC_PDAP_PCIE_PHY1 = 87,
	RDC_PDAP_HDMI_TX_AUDLNK_MSTR = 88,
	RDC_PDAP_CAN_FD2 = 89,
	RDC_PDAP_SPBA2 = 90,
	RDC_PDAP_QSPI = 91,
	RDC_PDAP_AUDIO_BLK_CTRL = 92,
	RDC_PDAP_SDMA1 = 93,
	RDC_PDAP_ENET1 = 94,
	RDC_PDAP_ENET2_TSN = 95,
	RDC_PDAP_ASRC = 97,
	RDC_PDAP_eCSPI1 = 98,
	RDC_PDAP_eCSPI2 = 99,
	RDC_PDAP_eCSPI3 = 100,
	RDC_PDAP_SAI7 = 101,
	RDC_PDAP_UART1 = 102,
	RDC_PDAP_UART3 = 104,
	RDC_PDAP_UART2 = 105,
	RDC_PDAP_PDM_MICFIL = 106,
	RDC_PDAP_AUDIO_XCVR_RX_eARC = 107,
	RDC_PDAP_SDMA3 = 109,
	RDC_PDAP_SPBA1 = 111,
};

enum csu_csl_idx {
	CSU_CSL_GPIO1 = 0,
	CSU_CSL_GPIO2 = 1,
	CSU_CSL_GPIO3 = 2,
	CSU_CSL_GPIO4 = 3,
	CSU_CSL_GPIO5 = 4,
	CSU_CSL_MU_2_A = 5,
	CSU_CSL_ANA_TSENSOR = 6,
	CSU_CSL_ANA_OSC = 7,
	CSU_CSL_WDOG1 = 8,
	CSU_CSL_WDOG2 = 9,
	CSU_CSL_WDOG3 = 10,
	CSU_CSL_GPT1 = 13,
	CSU_CSL_GPT2 = 14,
	CSU_CSL_GPT3 = 15,
	CSU_CSL_MU_2_B = 16,
	CSU_CSL_ROMCP = 17,
	CSU_CSL_MU_3_A = 18,
	CSU_CSL_IOMUXC = 19,
	CSU_CSL_IOMUXC_GPR = 20,
	CSU_CSL_OCOTP_CTRL = 21,
	CSU_CSL_ANA_PLL = 22,
	CSU_CSL_SNVS_HP = 23,
	CSU_CSL_CCM = 24,
	CSU_CSL_SRC = 25,
	CSU_CSL_GPC = 26,
	CSU_CSL_SEMAPHORE1 = 27,
	CSU_CSL_SEMAPHORE2 = 28,
	CSU_CSL_RDC = 29,
	CSU_CSL_CSU = 30,
	CSU_CSL_MU_3_B = 31,
	CSU_CSL_ISI = 32,
	CSU_CSL_ISP0 = 33,
	CSU_CSL_ISP1 = 34,
	CSU_CSL_IPS_Dewarp = 35,
	CSU_CSL_MIPI_CSI0 = 36,
	CSU_CSL_HSIOMIX_BLK_CTL	= 37,
	CSU_CSL_PWM1 = 38,
	CSU_CSL_PWM2 = 39,
	CSU_CSL_PWM3 = 40,
	CSU_CSL_PWM4 = 41,
	CSU_CSL_System_Counter_RD = 42,
	CSU_CSL_System_Counter_CMP = 43,
	CSU_CSL_System_Counter_CTRL = 44,
	CSU_CSL_I2C5 = 45,
	CSU_CSL_GPT6 = 46,
	CSU_CSL_GPT5 = 47,
	CSU_CSL_GPT4 = 48,
	CSU_CSL_MIPI_CSI1 = 49,
	CSU_CSL_MIPI_DSI0 = 50,
	CSU_CSL_MEDIAMIX_BLK_CTL = 51,
	CSU_CSL_LCDIF1 = 52,
	CSU_CSL_eDMA_Management_Page = 53,
	CSU_CSL_eDMA_Channels_15_0 = 54,
	CSU_CSL_eDMA_Channels_31_16 = 55,
	CSU_CSL_TZASC = 56,
	CSU_CSL_I2C6 = 57,
	CSU_CSL_CAAM = 58,
	CSU_CSL_LCDIF2 = 59,
	CSU_CSL_PERFMON1 = 60,
	CSU_CSL_PERFMON2 = 61,
	CSU_CSL_NOC_BLK_CTL = 62,
	CSU_CSL_QoSC = 63,
	CSU_CSL_LVDS0 = 64,
	CSU_CSL_LVDS1 = 65,
	CSU_CSL_I2C1 = 66,
	CSU_CSL_I2C2 = 67,
	CSU_CSL_I2C3 = 68,
	CSU_CSL_I2C4 = 69,
	CSU_CSL_UART4 = 70,
	CSU_CSL_HDMI_TX = 71,
	CSU_CSL_IRQ_STEER_Audio_Processor = 72,
	CSU_CSL_SDMA2 = 73,
	CSU_CSL_MU_1_A = 74,
	CSU_CSL_MU_1_B = 75,
	CSU_CSL_SEMAPHORE_HS = 76,
	CSU_CSL_SAI1 = 78,
	CSU_CSL_SAI2 = 79,
	CSU_CSL_SAI3 = 80,
	CSU_CSL_CAN_FD1 = 81,
	CSU_CSL_SAI5 = 82,
	CSU_CSL_SAI6 = 83,
	CSU_CSL_uSDHC1 = 84,
	CSU_CSL_uSDHC2 = 85,
	CSU_CSL_uSDHC3 = 86,
	CSU_CSL_PCIE_PHY1 = 87,
	CSU_CSL_HDMI_TX_AUDLNK_MSTR = 88,
	CSU_CSL_CAN_FD2 = 89,
	CSU_CSL_SPBA2 = 90,
	CSU_CSL_QSPI = 91,
	CSU_CSL_AUDIO_BLK_CTRL = 92,
	CSU_CSL_SDMA1 = 93,
	CSU_CSL_ENET1 = 94,
	CSU_CSL_ENET2_TSN = 95,
	CSU_CSL_ASRC = 97,
	CSU_CSL_eCSPI1 = 98,
	CSU_CSL_eCSPI2 = 99,
	CSU_CSL_eCSPI3 = 100,
	CSU_CSL_SAI7 = 101,
	CSU_CSL_UART1 = 102,
	CSU_CSL_UART3 = 104,
	CSU_CSL_UART2 = 105,
	CSU_CSL_PDM_MICFIL = 106,
	CSU_CSL_AUDIO_XCVR_RX_eARC = 107,
	CSU_CSL_SDMA3 = 109,
	CSU_CSL_SPBA1 = 111,
	CSU_CSL_OCRAM_A = 113,
	CSU_CSL_OCRAM = 118,
	CSU_CSL_OCRAM_S = 119,
	CSU_CSL_VPU = 120,
};

enum csu_sa_idx {
	CSU_SA_M7 = 1 ,
	CSU_SA_SDMA1 = 2 ,
	CSU_SA_PCIE_CTRL1 = 3 ,
	CSU_SA_USB1 = 4 ,
	CSU_SA_USB2 = 6 ,
	CSU_SA_APB_HDMA = 8 ,
	CSU_SA_ENET1 = 9 ,
	CSU_SA_USDHC1 = 10 ,
	CSU_SA_USDHC2 = 11 ,
	CSU_SA_USDHC3 = 12 ,
	CSU_SA_HUGO = 13 ,
	CSU_SA_DAP = 14 ,
	CSU_SA_SDMA2 = 15,
	CSU_SA_CAAM = 16 ,
	CSU_SA_SDMA3 = 17 ,
	CSU_SA_LCDIF1 = 18 ,
	CSU_SA_ISI = 19 ,
	CSU_SA_NPU = 20 ,
	CSU_SA_LCDIF2 = 21 ,
	CSU_SA_HDMI_TX = 22 ,
	CSU_SA_ENET2 = 23 ,
	CSU_SA_GPU3D = 24 ,
	CSU_SA_GPU2D = 25 ,
	CSU_SA_VPU_G1 = 26 ,
	CSU_SA_VPU_G2 = 27 ,
	CSU_SA_VPU_VC8000E = 28 ,
	CSU_SA_AUDIO_EDMA = 29 ,
	CSU_SA_ISP1 = 30 ,
	CSU_SA_ISP2 = 31 ,
	CSU_SA_DEWARP = 32 ,
	CSU_SA_GIC500 = 33 ,
};
#endif /* IMX_SEC_DEF_H */
