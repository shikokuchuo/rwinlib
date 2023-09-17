/**
 * \file psa_util.h
 *
 * \brief Utility functions for the use of the PSA Crypto library.
 *
 * \warning This function is not part of the public API and may
 *          change at any time.
 */
/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#ifndef MBEDTLS_PSA_UTIL_H
#define MBEDTLS_PSA_UTIL_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_PSA_CRYPTO_C)

#include "psa/crypto.h"

#include "mbedtls/ecp.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/oid.h"
#include "mbedtls/error.h"

#include <string.h>

static inline psa_key_type_t mbedtls_psa_translate_cipher_type(
    mbedtls_cipher_type_t cipher)
{
    switch (cipher) {
        case MBEDTLS_CIPHER_AES_128_CCM:
        case MBEDTLS_CIPHER_AES_192_CCM:
        case MBEDTLS_CIPHER_AES_256_CCM:
        case MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG:
        case MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG:
        case MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG:
        case MBEDTLS_CIPHER_AES_128_GCM:
        case MBEDTLS_CIPHER_AES_192_GCM:
        case MBEDTLS_CIPHER_AES_256_GCM:
        case MBEDTLS_CIPHER_AES_128_CBC:
        case MBEDTLS_CIPHER_AES_192_CBC:
        case MBEDTLS_CIPHER_AES_256_CBC:
        case MBEDTLS_CIPHER_AES_128_ECB:
        case MBEDTLS_CIPHER_AES_192_ECB:
        case MBEDTLS_CIPHER_AES_256_ECB:
            return PSA_KEY_TYPE_AES;

        default:
            return 0;
    }
}

static inline psa_algorithm_t mbedtls_psa_translate_cipher_mode(
    mbedtls_cipher_mode_t mode, size_t taglen)
{
    switch (mode) {
        case MBEDTLS_MODE_ECB:
            return PSA_ALG_ECB_NO_PADDING;
        case MBEDTLS_MODE_GCM:
            return PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, taglen);
        case MBEDTLS_MODE_CCM:
            return PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, taglen);
        case MBEDTLS_MODE_CCM_STAR_NO_TAG:
            return PSA_ALG_CCM_STAR_NO_TAG;
        case MBEDTLS_MODE_CBC:
            if (taglen == 0) {
                return PSA_ALG_CBC_NO_PADDING;
            } else {
                return 0;
            }
        default:
            return 0;
    }
}

static inline psa_key_usage_t mbedtls_psa_translate_cipher_operation(
    mbedtls_operation_t op)
{
    switch (op) {
        case MBEDTLS_ENCRYPT:
            return PSA_KEY_USAGE_ENCRYPT;
        case MBEDTLS_DECRYPT:
            return PSA_KEY_USAGE_DECRYPT;
        default:
            return 0;
    }
}

static inline psa_algorithm_t mbedtls_psa_translate_md(mbedtls_md_type_t md_alg)
{
    switch (md_alg) {
#if defined(MBEDTLS_MD5_C) || defined(PSA_WANT_ALG_MD5)
        case MBEDTLS_MD_MD5:
            return PSA_ALG_MD5;
#endif
#if defined(MBEDTLS_SHA1_C) || defined(PSA_WANT_ALG_SHA_1)
        case MBEDTLS_MD_SHA1:
            return PSA_ALG_SHA_1;
#endif
#if defined(MBEDTLS_SHA224_C) || defined(PSA_WANT_ALG_SHA_224)
        case MBEDTLS_MD_SHA224:
            return PSA_ALG_SHA_224;
#endif
#if defined(MBEDTLS_SHA256_C) || defined(PSA_WANT_ALG_SHA_256)
        case MBEDTLS_MD_SHA256:
            return PSA_ALG_SHA_256;
#endif
#if defined(MBEDTLS_SHA384_C) || defined(PSA_WANT_ALG_SHA_384)
        case MBEDTLS_MD_SHA384:
            return PSA_ALG_SHA_384;
#endif
#if defined(MBEDTLS_SHA512_C) || defined(PSA_WANT_ALG_SHA_512)
        case MBEDTLS_MD_SHA512:
            return PSA_ALG_SHA_512;
#endif
#if defined(MBEDTLS_RIPEMD160_C) || defined(PSA_WANT_ALG_RIPEMD160)
        case MBEDTLS_MD_RIPEMD160:
            return PSA_ALG_RIPEMD160;
#endif
        case MBEDTLS_MD_NONE:
            return 0;
        default:
            return 0;
    }
}

static inline int mbedtls_psa_get_ecc_oid_from_id(
    psa_ecc_family_t curve, size_t bits,
    char const **oid, size_t *oid_len)
{
    switch (curve) {
        case PSA_ECC_FAMILY_SECP_R1:
            switch (bits) {
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED)
                case 192:
                    *oid = MBEDTLS_OID_EC_GRP_SECP192R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP192R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP192R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED)
                case 224:
                    *oid = MBEDTLS_OID_EC_GRP_SECP224R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP224R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP224R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED)
                case 256:
                    *oid = MBEDTLS_OID_EC_GRP_SECP256R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP256R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
                case 384:
                    *oid = MBEDTLS_OID_EC_GRP_SECP384R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP384R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP384R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED)
                case 521:
                    *oid = MBEDTLS_OID_EC_GRP_SECP521R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP521R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP521R1_ENABLED */
            }
            break;
        case PSA_ECC_FAMILY_SECP_K1:
            switch (bits) {
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED)
                case 192:
                    *oid = MBEDTLS_OID_EC_GRP_SECP192K1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP192K1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP192K1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED)
                case 224:
                    *oid = MBEDTLS_OID_EC_GRP_SECP224K1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP224K1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP224K1_ENABLED */
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED)
                case 256:
                    *oid = MBEDTLS_OID_EC_GRP_SECP256K1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_SECP256K1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_SECP256K1_ENABLED */
            }
            break;
        case PSA_ECC_FAMILY_BRAINPOOL_P_R1:
            switch (bits) {
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED)
                case 256:
                    *oid = MBEDTLS_OID_EC_GRP_BP256R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_BP256R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_BP256R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED)
                case 384:
                    *oid = MBEDTLS_OID_EC_GRP_BP384R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_BP384R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_BP384R1_ENABLED */
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED)
                case 512:
                    *oid = MBEDTLS_OID_EC_GRP_BP512R1;
                    *oid_len = MBEDTLS_OID_SIZE(MBEDTLS_OID_EC_GRP_BP512R1);
                    return 0;
#endif /* MBEDTLS_ECP_DP_BP512R1_ENABLED */
            }
            break;
    }
    (void) oid;
    (void) oid_len;
    return -1;
}

#define MBEDTLS_PSA_MAX_EC_PUBKEY_LENGTH \
    PSA_KEY_EXPORT_ECC_PUBLIC_KEY_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)

#define MBEDTLS_PSA_MAX_EC_KEY_PAIR_LENGTH \
    PSA_KEY_EXPORT_ECC_KEY_PAIR_MAX_SIZE(PSA_VENDOR_ECC_MAX_CURVE_BITS)

typedef int mbedtls_f_rng_t(void *p_rng, unsigned char *output, size_t output_size);

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)

int mbedtls_psa_get_random(void *p_rng,
                           unsigned char *output,
                           size_t output_size);

#define MBEDTLS_PSA_RANDOM_STATE NULL

#else /* !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

#if defined(MBEDTLS_CTR_DRBG_C)
#include "mbedtls/ctr_drbg.h"
typedef mbedtls_ctr_drbg_context mbedtls_psa_drbg_context_t;
static mbedtls_f_rng_t *const mbedtls_psa_get_random = mbedtls_ctr_drbg_random;
#elif defined(MBEDTLS_HMAC_DRBG_C)
#include "mbedtls/hmac_drbg.h"
typedef mbedtls_hmac_drbg_context mbedtls_psa_drbg_context_t;
static mbedtls_f_rng_t *const mbedtls_psa_get_random = mbedtls_hmac_drbg_random;
#endif
extern mbedtls_psa_drbg_context_t *const mbedtls_psa_random_state;

#define MBEDTLS_PSA_RANDOM_STATE mbedtls_psa_random_state

#endif /* !defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG) */

typedef struct {
    psa_status_t psa_status;
    int16_t mbedtls_error;
} mbedtls_error_pair_t;

#if !defined(MBEDTLS_MD_C) || !defined(MBEDTLS_MD5_C) || defined(MBEDTLS_USE_PSA_CRYPTO)
extern const mbedtls_error_pair_t psa_to_md_errors[4];
#endif

#if defined(MBEDTLS_LMS_C)
extern const mbedtls_error_pair_t psa_to_lms_errors[3];
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) || defined(MBEDTLS_SSL_PROTO_TLS1_3)
extern const mbedtls_error_pair_t psa_to_ssl_errors[7];
#endif

#if defined(PSA_WANT_KEY_TYPE_RSA_PUBLIC_KEY) ||    \
    defined(PSA_WANT_KEY_TYPE_RSA_KEY_PAIR)
extern const mbedtls_error_pair_t psa_to_pk_rsa_errors[8];
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
extern const mbedtls_error_pair_t psa_to_pk_ecdsa_errors[7];
#endif

int psa_generic_status_to_mbedtls(psa_status_t status);

int psa_status_to_mbedtls(psa_status_t status,
                          const mbedtls_error_pair_t *local_translations,
                          size_t local_errors_num,
                          int (*fallback_f)(psa_status_t));

int psa_pk_status_to_mbedtls(psa_status_t status);

#define PSA_TO_MBEDTLS_ERR_LIST(status, error_list, fallback_f)       \
    psa_status_to_mbedtls(status, error_list,                         \
                          sizeof(error_list)/sizeof(error_list[0]),   \
                          fallback_f)

#endif /* MBEDTLS_PSA_CRYPTO_C */
#endif /* MBEDTLS_PSA_UTIL_H */
