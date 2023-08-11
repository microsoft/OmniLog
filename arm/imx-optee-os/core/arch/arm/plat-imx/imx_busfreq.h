/* SPDX-License-Identifier: BSD-2-Clause */
/**
 * @copyright 2018 NXP
 *
 * @file    imx_busfreq.h
 *
 * @brief   Busfreq interface.
 */
#ifndef __BUSFREQ_H__
#define __BUSFREQ_H__

TEE_Result busfreq_change(uint32_t freq, uint32_t dll_off);

#endif /* __BUSFREQ_H__ */
