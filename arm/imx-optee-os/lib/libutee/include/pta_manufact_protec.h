/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Manufacturing Protection PTA shared UUID and Commands.
 */
#ifndef PTA_MP_H
#define PTA_MP_H

/* PTA UUID generated at http://www.itu.int/ITU-T/asn1/uuid.html */
#define PTA_MANUFACT_PROTEC_UUID { 0x83268b7c, 0x85e3, 0x11e8, \
		{ 0xad, 0xc0, 0xfa, 0x7a, 0xe0, 0x1b, 0xbe, 0xbc} }

/*
 * Commands Definition
 */
/* Buffer Signature - return MPMR */
#define PTA_MP_CMD_SIGNATURE_MPMR	0
/* Get the Public Key */
#define PTA_MP_CMD_GET_PUBLIC_KEY	1

#endif /* PTA_MANUFACT_PROTEC_H */
