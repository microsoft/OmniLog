/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   CAAM Cryptographic APIs extension not available thru standard TEE
 *         Cryptographic APIs.
 */
#ifndef __CRYPTO_EXTENSTION_H__
#define __CRYPTO_EXTENSTION_H__

#include <tee_api_types.h>

/*
 * Definition of a crypto buffer type
 */
struct cryptobuf {
	uint8_t *data;
	size_t length;
};

#ifdef CFG_CRYPTO_DRV_MP
struct crypto_mp_sign {
	struct cryptobuf message;   /* Message to sign */
	struct cryptobuf signature; /* Message's Signature */
};

/*
 * Export the MPMR content.
 * We assume that it is filled with message given in parameter.
 * It contains 32 registers of 8 bits (32 bytes).
 *
 * @mpmr  [out] MPMR buffer read
 */
TEE_Result crypto_mp_export_mpmr(struct cryptobuf *mpmr);

/*
 * Export the Manufacturing Protection Public Key.
 *
 * @pubkey  [out] Public key read
 */
TEE_Result crypto_mp_export_publickey(struct cryptobuf *pubkey);

/*
 * MPSign function.
 * This function takes the value in the MPMR if it exists
 * and concatenates any additional data (certificate).
 * The signature over the message is done with the private key.
 *
 * @sdata   [in/out] MP Signature structure
 */
TEE_Result crypto_mp_sign(struct crypto_mp_sign *sdata);
#endif /* CFG_CRYPTO_DRV_MP */

#ifdef CFG_CRYPTO_DRV_SM
/*
 * Free a full Secure Memory partition and its pages
 *
 * @partition  Secure Memory partition
 */
TEE_Result caam_sm_free_partition(unsigned int partition);

/*
 * Secure Memory Page(s)/Partition definition
 */
struct crypto_sm_page {
	unsigned int partition;    /* Partition number */
	unsigned int page;         /* Page number */
	unsigned int nb_pages;     /* Number of pages used */
};
#endif /* CFG_CRYPTO_DRV_SM */


#ifdef CFG_CRYPTO_DRV_BLOB
/*
 * Blob size padding in bytes
 */
#define BLOB_BKEK_SIZE	32
#define BLOB_MAC_SIZE	16
#define BLOB_PAD_SIZE	(BLOB_BKEK_SIZE + BLOB_MAC_SIZE)

/*
 * Blob Key modifier is 128 bits
 */
#define BLOB_KEY_MODIFIER_BITS	128

/*
 * Blob encryption/decryption type
 */
enum crypto_blob_type {
	BLOB_RED = 0,   /* Red Blob mode   - data in plain text */
	BLOB_BLACK_ECB, /* Black Blob mode - data encrypted in AES ECB */
	BLOB_BLACK_CCM, /* Black Blod mode - data encrypted in AES CCM */
};

/*
 * Blob data structure where
 * if encapsulation:
 *       - payload is the input
 *       - blob is the output
 * if decapsulation:
 *       - blob is the input
 *       - payload is the output
 */
struct crypto_blob {
	enum crypto_blob_type type;                /* Blob Type */
	uint32_t key[BLOB_KEY_MODIFIER_BITS / 32]; /* Blob Key modifier */
	struct cryptobuf payload;                  /* Payload */
	struct cryptobuf blob;                     /* Blob */
};

#ifdef CFG_CRYPTO_DRV_SM
/*
 * Blob encapsulation using CAAM Secure Memory.
 *
 * @blob_data  [in/out] Blob data
 */
TEE_Result caam_blob_sm_encapsulate(struct crypto_blob *blob,
				    struct crypto_sm_page *sm_page);
#endif /* CFG_CRYPTO_DRV_SM */
#endif /* CFG_CRYPTO_DRV_BLOB */

#endif /* __CRYPTO_EXTENSTION_H__ */
