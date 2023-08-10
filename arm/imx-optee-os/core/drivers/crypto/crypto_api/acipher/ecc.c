// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2018-2019 NXP
 *
 * Brief   Crypto ECC interface implementation to enable HW driver.
 */
#include <crypto/crypto.h>
#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <tee/tee_cryp_utl.h>
#include <utee_defines.h>

/*
 * Returns the key size in bits for the given ECC curve
 *
 * @curve   ECC Curve ID
 */
static size_t get_ecc_keysize(uint32_t curve)
{
	size_t size_sec = 0;

	switch (curve) {
	case TEE_ECC_CURVE_NIST_P192:
		size_sec = 192;
		break;

	case TEE_ECC_CURVE_NIST_P224:
		size_sec = 224;
		break;

	case TEE_ECC_CURVE_NIST_P256:
		size_sec = 256;
		break;

	case TEE_ECC_CURVE_NIST_P384:
		size_sec = 384;
		break;

	case TEE_ECC_CURVE_NIST_P521:
		/* Key size is 528 bits to be byte aligned */
		size_sec = 528;
		break;

	default:
		break;
	}

	return size_sec;
}

/*
 * Verify if the cryptographic algorithm @aglo is valid for
 * the ECC curve
 *
 * @curve   ECC curve
 * @algo    Cryptographic algorithm
 */
static int algo_isvalid(uint32_t curve, uint32_t algo)
{
	int ret = -1;
	uint8_t algo_op = 0;
	uint8_t algo_id = 0;
	uint8_t algo_curve = 0;

	algo_op = TEE_ALG_GET_CLASS(algo);
	algo_id = TEE_ALG_GET_MAIN_ALG(algo);
	algo_curve = TEE_ALG_GET_DIGEST_HASH(algo);

	/* Check first if the aglo operation and the algo id are correct */
	if ((algo_op == TEE_OPERATION_ASYMMETRIC_SIGNATURE &&
	     algo_id == TEE_MAIN_ALGO_ECDSA) ||
	    (algo_op == TEE_OPERATION_KEY_DERIVATION &&
	     algo_id == TEE_MAIN_ALGO_ECDH)) {
		if (curve == algo_curve)
			ret = 0;
	}

	CRYPTO_TRACE("Validate algo 0x%" PRIx32 " with curve %d return %d",
		     algo, curve, ret);

	return ret;
}

/*
 * Allocate an ECC keypair
 *
 * @key        Keypair
 * @size_bits  Key size in bits
 */
TEE_Result crypto_acipher_alloc_ecc_keypair(struct ecc_keypair *key,
					    size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_ecc *ecc = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Bad parameters (key @%p)(size %zu bits)", key,
			     size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc)
		ret = ecc->alloc_keypair(key, size_bits);

	CRYPTO_TRACE("ECC Keypair (%zu bits) alloc ret = 0x%" PRIx32, size_bits,
		     ret);
	return ret;
}

/*
 * Allocate an ECC public key
 *
 * @key        Public Key
 * @size_bits  Key size in bits
 */
TEE_Result crypto_acipher_alloc_ecc_public_key(struct ecc_public_key *key,
					       size_t size_bits)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_ecc *ecc = NULL;

	if (!key || !size_bits) {
		CRYPTO_TRACE("Bad parameters (key @%p)(size %zu bits)", key,
			     size_bits);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc)
		ret = ecc->alloc_publickey(key, size_bits);

	CRYPTO_TRACE("ECC Public Key (%zu bits) alloc ret = 0x%" PRIx32,
		     size_bits, ret);
	return ret;
}

/*
 * Free an ECC public key
 *
 * @key   Public Key
 */
void crypto_acipher_free_ecc_public_key(struct ecc_public_key *key)
{
	struct drvcrypt_ecc *ecc = NULL;

	if (key) {
		ecc = drvcrypt_get_ops(CRYPTO_ECC);
		if (ecc) {
			CRYPTO_TRACE("ECC Public Key free");
			ecc->free_publickey(key);
		}
	}
}

/*
 * Generates an ECC keypair
 *
 * @key   Keypair
 */
TEE_Result crypto_acipher_gen_ecc_key(struct ecc_keypair *key,
				      size_t __unused key_size)
{
	TEE_Result ret = TEE_ERROR_NOT_IMPLEMENTED;
	struct drvcrypt_ecc *ecc = NULL;

	/* Check input parameters */
	if (!key) {
		CRYPTO_TRACE("Parameters error key is NULL");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc)
		ret = ecc->gen_keypair(key, get_ecc_keysize(key->curve));

	CRYPTO_TRACE("ECC Keypair (%zu bits) generate ret = 0x%" PRIx32,
		     size_bits, ret);

	return ret;
}

/*
 * Sign the message with the ECC Key given by the Keypair
 *
 * @algo       ECC algorithm
 * @key        ECC Keypair
 * @msg        Message to sign
 * @msg_len    Length of the message (bytes)
 * @sig        Signature
 * @sig_len    [in/out] Length of the signature (bytes)
 */
TEE_Result crypto_acipher_ecc_sign(uint32_t algo, struct ecc_keypair *key,
				   const uint8_t *msg, size_t msg_len,
				   uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc *ecc = NULL;
	struct drvcrypt_sign_data sdata = {};
	size_t size_bits = 0;
	size_t size_bytes = 0;

	/* Verify first if the input parameters */
	if (!key || !msg || !sig || !sig_len) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo_isvalid(key->curve, algo) != 0)
		return ret;

	size_bits = get_ecc_keysize(key->curve);
	if (size_bits == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the signature length function of the key size */
	size_bytes = size_bits / 8;
	if (*sig_len < 2 * size_bytes) {
		CRYPTO_TRACE("Length (%zu) too short expected %zu bytes",
			     *sig_len, 2 * size_bytes);
		*sig_len = 2 * size_bytes;
		return TEE_ERROR_SHORT_BUFFER;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo = algo;
		sdata.key = key;
		sdata.size_sec = size_bytes;
		sdata.message.data = (uint8_t *)msg;
		sdata.message.length = msg_len;
		sdata.signature.data = (uint8_t *)sig;
		sdata.signature.length = *sig_len;

		ret = ecc->sign(&sdata);

		/* Set the signature length */
		*sig_len = sdata.signature.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Sign algo (0x%" PRIx32 ") returned 0x%" PRIx32, algo,
		     ret);

	return ret;
}

/*
 * Verify the signature of the message.
 * Message is signed with the given Public Key.
 *
 * @algo       ECC algorithm
 * @key        ECC Public key
 * @msg        Message to sign
 * @msg_len    Length of the message (bytes)
 * @sig        Signature
 * @sig_len    Length of the signature (bytes)
 */
TEE_Result crypto_acipher_ecc_verify(uint32_t algo, struct ecc_public_key *key,
				     const uint8_t *msg, size_t msg_len,
				     const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc *ecc = NULL;
	struct drvcrypt_sign_data sdata = {};
	size_t size_bits = 0;
	size_t size_bytes = 0;

	/* Verify first if the input parameters */
	if (!key || !msg || !sig) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (algo_isvalid(key->curve, algo) != 0)
		return ret;

	size_bits = get_ecc_keysize(key->curve);
	if (size_bits == 0)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Verify the signature length function of the key size */
	size_bytes = size_bits / 8;
	if (sig_len != 2 * size_bytes) {
		CRYPTO_TRACE("Length (%zu) is invalid expected %zu bytes",
			     sig_len, 2 * size_bytes);
		return TEE_ERROR_SIGNATURE_INVALID;
	}

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Signature structure data
		 */
		sdata.algo = algo;
		sdata.key = key;
		sdata.size_sec = size_bytes;
		sdata.message.data = (uint8_t *)msg;
		sdata.message.length = msg_len;
		sdata.signature.data = (uint8_t *)sig;
		sdata.signature.length = sig_len;

		ret = ecc->verify(&sdata);
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Verify algo (0x%" PRIx32 ") returned 0x%" PRIx32, algo,
		     ret);

	return ret;
}

/*
 * Compute the shared secret data from ECC Private key and Public Key
 *
 * @private_key  ECC Private key
 * @public_key   ECC Public key
 * @secret       Secret
 * @secret_len   Length of the secret (bytes)
 */
TEE_Result crypto_acipher_ecc_shared_secret(struct ecc_keypair *private_key,
					    struct ecc_public_key *public_key,
					    void *secret,
					    unsigned long *secret_len)
{
	TEE_Result ret = TEE_ERROR_BAD_PARAMETERS;
	struct drvcrypt_ecc *ecc = NULL;
	struct drvcrypt_secret_data sdata = {};
	size_t size_bits = 0;

	/* Verify first if the input parameters */
	if (!private_key || !public_key || !secret || !secret_len) {
		CRYPTO_TRACE("Input parameters reference error");
		return ret;
	}

	if (private_key->curve != public_key->curve) {
		CRYPTO_TRACE("Private Key curve (%d) != Public Key curve (%d)",
			     private_key->curve, public_key->curve);
		return ret;
	}

	size_bits = get_ecc_keysize(public_key->curve);
	if (!size_bits)
		return ret;

	if (*secret_len < (size_bits / 8))
		return TEE_ERROR_SHORT_BUFFER;

	ecc = drvcrypt_get_ops(CRYPTO_ECC);
	if (ecc) {
		/*
		 * Prepare the Secret structure data
		 */
		sdata.key_priv = private_key;
		sdata.key_pub = public_key;
		sdata.size_sec = size_bits / 8;
		sdata.secret.data = secret;
		sdata.secret.length = *secret_len;

		ret = ecc->shared_secret(&sdata);

		/* Set the secret length */
		*secret_len = sdata.secret.length;
	} else {
		ret = TEE_ERROR_NOT_IMPLEMENTED;
	}

	CRYPTO_TRACE("Shared Secret returned 0x%" PRIx32, ret);

	return ret;
}
