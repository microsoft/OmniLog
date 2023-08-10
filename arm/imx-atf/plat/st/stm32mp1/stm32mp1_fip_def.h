/*
 * Copyright (C) 2021, STMicroelectronics - All Rights Reserved
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef STM32MP1_FIP_DEF_H
#define STM32MP1_FIP_DEF_H

#define STM32MP_DDR_S_SIZE		U(0x01E00000)	/* 30 MB */
#define STM32MP_DDR_SHMEM_SIZE		U(0x00200000)	/* 2 MB */

#define STM32MP_BL2_SIZE		U(0x0001B000)	/* 108 KB for BL2 */
#define STM32MP_BL2_DTB_SIZE		U(0x00006000)	/* 24 KB for DTB */
#define STM32MP_BL32_SIZE		U(0x00019000)	/* 100 KB for BL32 */
#define STM32MP_BL32_DTB_SIZE		U(0x00005000)	/* 20 KB for DTB */
#define STM32MP_FW_CONFIG_MAX_SIZE	PAGE_SIZE	/* 4 KB for FCONF DTB */
#define STM32MP_HW_CONFIG_MAX_SIZE	U(0x40000)	/* 256 KB for HW config DTB */

#define STM32MP_BL2_BASE		(STM32MP_SEC_SYSRAM_BASE + \
					 STM32MP_SEC_SYSRAM_SIZE - \
					 STM32MP_BL2_SIZE)

#define STM32MP_BL2_DTB_BASE		(STM32MP_BL2_BASE - \
					 STM32MP_BL2_DTB_SIZE)

#define STM32MP_BL32_DTB_BASE		STM32MP_SYSRAM_BASE

#define STM32MP_BL32_BASE		(STM32MP_BL32_DTB_BASE + \
					 STM32MP_BL32_DTB_SIZE)


#if defined(IMAGE_BL2)
#define STM32MP_DTB_SIZE		STM32MP_BL2_DTB_SIZE
#define STM32MP_DTB_BASE		STM32MP_BL2_DTB_BASE
#endif
#if defined(IMAGE_BL32)
#define STM32MP_DTB_SIZE		STM32MP_BL32_DTB_SIZE
#define STM32MP_DTB_BASE		STM32MP_BL32_DTB_BASE
#endif

#ifdef AARCH32_SP_OPTEE
#define STM32MP_OPTEE_BASE		STM32MP_SEC_SYSRAM_BASE

#define STM32MP_OPTEE_SIZE		(STM32MP_BL2_DTB_BASE -  \
					 STM32MP_OPTEE_BASE)
#endif

#define STM32MP_FW_CONFIG_BASE		(STM32MP_SYSRAM_BASE + \
					 STM32MP_SYSRAM_SIZE - \
					 PAGE_SIZE)
#define STM32MP_HW_CONFIG_BASE		(STM32MP_BL33_BASE + \
					STM32MP_BL33_MAX_SIZE)

/*
 * MAX_MMAP_REGIONS is usually:
 * BL stm32mp1_mmap size + mmap regions in *_plat_arch_setup
 */
#if defined(IMAGE_BL32)
#define MAX_MMAP_REGIONS		10
#endif

/*******************************************************************************
 * STM32MP1 RAW partition offset for MTD devices
 ******************************************************************************/
#define STM32MP_NOR_FIP_OFFSET		U(0x00080000)
#define STM32MP_NAND_FIP_OFFSET		U(0x00200000)

#endif /* STM32MP1_FIP_DEF_H */
