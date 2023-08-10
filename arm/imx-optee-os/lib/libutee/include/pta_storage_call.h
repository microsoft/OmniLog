/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2022, Sarbartha Banerjee
 */

#ifndef __PTA_STORAGE_CALL_H
#define __PTA_STORAGE_CALL_H

#define PTA_NAME "storage_call.pta"
#define PTA_STORAGE_CALL_UUID {0x166829b7, 0x983c, 0x42e3, { \
							0x85, 0x5e, 0xb6, 0x2e, 0xf0, 0x35, 0x13, 0xee} }

/* Interface to the storage call pseudo-ta, which is used by libutee to store
* pending log data from trusted buffer to sdcard storage
*/

#define PTA_STORAGE_CALL_CONFIG_BUFFER 0x0
#define PTA_STORAGE_CALL_RET_BUF_STATUS 0x1
#define PTA_STORAGE_CALL_DUMP 0x2

#define TA_STACK_SIZE (1*1024*1024)
#endif
