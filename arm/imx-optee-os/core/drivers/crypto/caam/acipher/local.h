/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2018-2020 NXP
 *
 * CAAM Cipher Local header.
 */
#ifndef __LOCAL_H__
#define __LOCAL_H__

#include "caam_common.h"

/*
 * Prime generator structure for RSA
 */
struct prime_rsa {
	uint8_t era;	   /* CAAM Era version */
	size_t key_size;   /* Key size in bits */
	struct caambuf *e; /* Key exponent e */
	struct caambuf *p; /* Prime p */
	struct caambuf *q; /* Prime q (can be NULL of only p asked) */
};

/*
 * Generate RSA Prime Numbers
 * Algorithm based on the Chapter B.3.3 of the FIPS.184-6 specification
 *
 * @data  [in/out] Prime generation data
 */
enum caam_status caam_prime_rsa_gen(struct prime_rsa *data);

/*
 * Prime generator structure for DSA
 */
struct prime_dsa {
	struct caambuf *g; /* Generator g */
	struct caambuf *p; /* Prime p */
	struct caambuf *q; /* Prime q */
};

/*
 * Generate DSA Prime Number
 * Algorithm based on the Chapter A.1.2 of the FIPS.186-4 specification
 *
 * @data  [in/out] Prime generation data
 */
enum caam_status caam_prime_dsa_gen(struct prime_dsa *data);

#endif /* __LOCAL_H__ */
