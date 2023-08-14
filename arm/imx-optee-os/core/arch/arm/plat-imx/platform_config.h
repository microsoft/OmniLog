/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (C) 2015 Freescale Semiconductor, Inc.
 * Copyright (c) 2016, Wind River Systems.
 * All rights reserved.
 * Copyright 2019 NXP
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>
#include <imx-regs.h>
#include <imx.h>

#ifndef CFG_DDR_SIZE
#error "CFG_DDR_SIZE not defined"
#endif

#define STACK_ALIGNMENT			64
#define CONSOLE_UART_BASE		(CFG_UART_BASE)

/* For i.MX6 Quad SABRE Lite and Smart Device board */
#if defined(CFG_MX6QP) || defined(CFG_MX6Q) || defined(CFG_MX6D) || \
	defined(CFG_MX6DL) || defined(CFG_MX6S)
#include <config/imx6qdlsolo.h>
#elif defined(CFG_MX6SX)
#include <config/imx6sx.h>

/* For i.MX 6UltraLite and 6ULL EVK board */
#elif defined(CFG_MX6UL) || defined(CFG_MX6ULL)

#ifdef CFG_WITH_PAGER
#error "Pager not supported for platform mx6ulevk"
#endif
#ifdef CFG_WITH_LPAE
#error "LPAE not supported for now"
#endif
/* For i.MX 6SL */
#elif defined(CFG_MX6SL)
#include <config/imx6sl.h>
/* For i.MX 6SLL */
#elif defined(CFG_MX6SLL)
#include <config/imx6sll.h>
#endif

/*
 * Calculate Non Secure memory region, after Secure memory carved out.
 * Assumption is memory for TEE is 32M
 * Those defines are used to register dynamic shared memory
 * Currently enable only mscale family.
 */
#if defined(CFG_MX8MQ) || defined(CFG_MX8MM) || defined(CFG_MX8MN) ||          \
	defined(CFG_MX8MP)
#define DRAM0_NSEC_BASE CFG_DRAM_BASE
#define DRAM0_NSEC_SIZE (CFG_TZDRAM_START - CFG_DRAM_BASE)
#define DRAM1_NSEC_BASE (CFG_TZDRAM_START + 0x2000000)
#define DRAM1_NSEC_SIZE (CFG_DDR_SIZE - DRAM1_NSEC_BASE + CFG_DRAM_BASE)
#endif

#if defined(CFG_IMX_DEK_HAB) && !defined(DRAM0_NSEC_SIZE)
#warning HAB DEK Blob is enabled but it requires dynamic shared memory \
and this feature is not enabled !!
#endif
#endif /*PLATFORM_CONFIG_H*/
