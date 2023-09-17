/**
 *  Macros to express dependencies for code and tests that may use either the
 *  legacy API or PSA in various builds. This whole header file is currently
 *  for internal use only and both the header file and the macros it defines
 *  may change or be removed without notice.
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

#ifndef MBEDTLS_OR_PSA_HELPERS_H
#define MBEDTLS_OR_PSA_HELPERS_H

#include "mbedtls/build_info.h"
#if defined(MBEDTLS_PSA_CRYPTO_C)
#include "psa/crypto.h"
#endif /* MBEDTLS_PSA_CRYPTO_C */

#if defined(MBEDTLS_MD5_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_MD5))
#define MBEDTLS_HAS_ALG_MD5_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_RIPEMD160_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_RIPEMD160))
#define MBEDTLS_HAS_ALG_RIPEMD160_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA1_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_1))
#define MBEDTLS_HAS_ALG_SHA_1_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA224_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_224))
#define MBEDTLS_HAS_ALG_SHA_224_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA256_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256))
#define MBEDTLS_HAS_ALG_SHA_256_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA384_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_384))
#define MBEDTLS_HAS_ALG_SHA_384_VIA_LOWLEVEL_OR_PSA
#endif
#if defined(MBEDTLS_SHA512_C) || \
    (defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_512))
#define MBEDTLS_HAS_ALG_SHA_512_VIA_LOWLEVEL_OR_PSA
#endif

#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_MD5_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_MD5))
#define MBEDTLS_HAS_ALG_MD5_VIA_MD_OR_PSA
#endif
#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_RIPEMD160_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_RIPEMD160))
#define MBEDTLS_HAS_ALG_RIPEMD160_VIA_MD_OR_PSA
#endif
#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA1_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_1))
#define MBEDTLS_HAS_ALG_SHA_1_VIA_MD_OR_PSA
#endif
#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA224_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_224))
#define MBEDTLS_HAS_ALG_SHA_224_VIA_MD_OR_PSA
#endif
#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA256_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_256))
#define MBEDTLS_HAS_ALG_SHA_256_VIA_MD_OR_PSA
#endif
#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA384_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_384))
#define MBEDTLS_HAS_ALG_SHA_384_VIA_MD_OR_PSA
#endif
#if (defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA512_C)) || \
    (!defined(MBEDTLS_MD_C) && \
    defined(MBEDTLS_PSA_CRYPTO_C) && defined(PSA_WANT_ALG_SHA_512))
#define MBEDTLS_HAS_ALG_SHA_512_VIA_MD_OR_PSA
#endif

#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_MD5_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_MD5))
#define MBEDTLS_HAS_ALG_MD5_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_RIPEMD160_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_RIPEMD160))
#define MBEDTLS_HAS_ALG_RIPEMD160_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA1_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_1))
#define MBEDTLS_HAS_ALG_SHA_1_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA224_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_224))
#define MBEDTLS_HAS_ALG_SHA_224_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA256_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_256))
#define MBEDTLS_HAS_ALG_SHA_256_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA384_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_384))
#define MBEDTLS_HAS_ALG_SHA_384_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif
#if (!defined(MBEDTLS_USE_PSA_CRYPTO) && \
    defined(MBEDTLS_MD_C) && defined(MBEDTLS_SHA512_C)) || \
    (defined(MBEDTLS_USE_PSA_CRYPTO) && defined(PSA_WANT_ALG_SHA_512))
#define MBEDTLS_HAS_ALG_SHA_512_VIA_MD_OR_PSA_BASED_ON_USE_PSA
#endif

#endif /* MBEDTLS_OR_PSA_HELPERS_H */
