/**
 * \file mbedtls/config_adjust_legacy_crypto.h
 * \brief Adjust legacy configuration configuration
 *
 * Automatically enable certain dependencies. Generally, MBEDLTS_xxx
 * configurations need to be explicitly enabled by the user: enabling
 * MBEDTLS_xxx_A but not MBEDTLS_xxx_B when A requires B results in a
 * compilation error. However, we do automatically enable certain options
 * in some circumstances. One case is if MBEDTLS_xxx_B is an internal option
 * used to identify parts of a module that are used by other module, and we
 * don't want to make the symbol MBEDTLS_xxx_B part of the public API.
 * Another case is if A didn't depend on B in earlier versions, and we
 * want to use B in A but we need to preserve backward compatibility with
 * configurations that explicitly activate MBEDTLS_xxx_A but not
 * MBEDTLS_xxx_B.
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

#ifndef MBEDTLS_CONFIG_ADJUST_LEGACY_CRYPTO_H
#define MBEDTLS_CONFIG_ADJUST_LEGACY_CRYPTO_H

#if defined(MBEDTLS_MD_C)
#define MBEDTLS_MD_LIGHT
#endif

#if defined(MBEDTLS_ECJPAKE_C) || \
    defined(MBEDTLS_PEM_PARSE_C) || \
    defined(MBEDTLS_ENTROPY_C) || \
    defined(MBEDTLS_PK_C) || \
    defined(MBEDTLS_PKCS12_C) || \
    defined(MBEDTLS_RSA_C) || \
    defined(MBEDTLS_SSL_TLS_C) || \
    defined(MBEDTLS_X509_USE_C) || \
    defined(MBEDTLS_X509_CREATE_C)
#define MBEDTLS_MD_LIGHT
#endif

#if defined(MBEDTLS_ECP_C) || \
    defined(MBEDTLS_PK_PARSE_EC_EXTENDED) || \
    defined(MBEDTLS_PK_PARSE_EC_COMPRESSED) || \
    defined(MBEDTLS_PSA_BUILTIN_KEY_TYPE_ECC_KEY_PAIR_DERIVE)
#define MBEDTLS_ECP_LIGHT
#endif

#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_ECP_C)
#define MBEDTLS_PK_PARSE_EC_COMPRESSED
#endif

#if (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_ECDH)) || \
    (!defined(MBEDTLS_USE_PSA_CRYPTO) && defined(MBEDTLS_ECDH_C))
#define MBEDTLS_CAN_ECDH
#endif

#if !defined(MBEDTLS_USE_PSA_CRYPTO)
#if defined(MBEDTLS_ECDSA_C)
#define MBEDTLS_PK_CAN_ECDSA_SIGN
#define MBEDTLS_PK_CAN_ECDSA_VERIFY
#endif /* MBEDTLS_ECDSA_C */
#else /* MBEDTLS_USE_PSA_CRYPTO */
#if defined(PSA_WANT_ALG_ECDSA)
#if defined(PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC)
#define MBEDTLS_PK_CAN_ECDSA_SIGN
#endif /* PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC */
#if defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY)
#define MBEDTLS_PK_CAN_ECDSA_VERIFY
#endif /* PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY */
#endif /* PSA_WANT_ALG_ECDSA */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

#if defined(MBEDTLS_PK_CAN_ECDSA_VERIFY) || defined(MBEDTLS_PK_CAN_ECDSA_SIGN)
#define MBEDTLS_PK_CAN_ECDSA_SOME
#endif

#if defined(MBEDTLS_PSA_CRYPTO_C)
#define MBEDTLS_PSA_CRYPTO_CLIENT
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(MBEDTLS_PSA_CRYPTO_C) && defined(MBEDTLS_RSA_C)
#define MBEDTLS_PK_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_PK_PARSE_C
#endif

#if defined(MBEDTLS_ECP_DP_SECP521R1_ENABLED) || defined(PSA_WANT_ECC_SECP_R1_521)
#define MBEDTLS_ECP_HAVE_SECP521R1
#endif
#if defined(MBEDTLS_ECP_DP_BP512R1_ENABLED) || defined(PSA_WANT_ECC_BRAINPOOL_P_R1_512)
#define MBEDTLS_ECP_HAVE_BP512R1
#endif
#if defined(MBEDTLS_ECP_DP_CURVE448_ENABLED) || defined(PSA_WANT_ECC_MONTGOMERY_448)
#define MBEDTLS_ECP_HAVE_CURVE448
#endif
#if defined(MBEDTLS_ECP_DP_BP384R1_ENABLED) || defined(PSA_WANT_ECC_BRAINPOOL_P_R1_384)
#define MBEDTLS_ECP_HAVE_BP384R1
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED) || defined(PSA_WANT_ECC_SECP_R1_384)
#define MBEDTLS_ECP_HAVE_SECP384R1
#endif
#if defined(MBEDTLS_ECP_DP_BP256R1_ENABLED) || defined(PSA_WANT_ECC_BRAINPOOL_P_R1_256)
#define MBEDTLS_ECP_HAVE_BP256R1
#endif
#if defined(MBEDTLS_ECP_DP_SECP256K1_ENABLED) || defined(PSA_WANT_ECC_SECP_K1_256)
#define MBEDTLS_ECP_HAVE_SECP256K1
#endif
#if defined(MBEDTLS_ECP_DP_SECP256R1_ENABLED) || defined(PSA_WANT_ECC_SECP_R1_256)
#define MBEDTLS_ECP_HAVE_SECP256R1
#endif
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED) || defined(PSA_WANT_ECC_MONTGOMERY_255)
#define MBEDTLS_ECP_HAVE_CURVE25519
#endif
#if defined(MBEDTLS_ECP_DP_SECP224K1_ENABLED) || defined(PSA_WANT_ECC_SECP_K1_224)
#define MBEDTLS_ECP_HAVE_SECP224K1
#endif
#if defined(MBEDTLS_ECP_DP_SECP224R1_ENABLED) || defined(PSA_WANT_ECC_SECP_R1_224)
#define MBEDTLS_ECP_HAVE_SECP224R1
#endif
#if defined(MBEDTLS_ECP_DP_SECP192K1_ENABLED) || defined(PSA_WANT_ECC_SECP_K1_192)
#define MBEDTLS_ECP_HAVE_SECP192K1
#endif
#if defined(MBEDTLS_ECP_DP_SECP192R1_ENABLED) || defined(PSA_WANT_ECC_SECP_R1_192)
#define MBEDTLS_ECP_HAVE_SECP192R1
#endif

#if defined(MBEDTLS_ECP_C) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY))
#define MBEDTLS_PK_HAVE_ECC_KEYS
#endif /* MBEDTLS_PK_USE_PSA_EC_DATA || MBEDTLS_ECP_C */

#if defined(MBEDTLS_PK_PARSE_C) && defined(MBEDTLS_PKCS5_C) && defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_CIPHER_PADDING_PKCS7
#endif

#endif /* MBEDTLS_CONFIG_ADJUST_LEGACY_CRYPTO_H */
