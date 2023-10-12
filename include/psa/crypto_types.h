/**
 * \file psa/crypto_types.h
 *
 * \brief PSA cryptography module: type aliases.
 *
 * \note This file may not be included directly. Applications must
 * include psa/crypto.h. Drivers must include the appropriate driver
 * header file.
 *
 * This file contains portable definitions of integral types for properties
 * of cryptographic keys, designations of cryptographic algorithms, and
 * error codes returned by the library.
 *
 * This header file does not declare any function.
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

#ifndef PSA_CRYPTO_TYPES_H
#define PSA_CRYPTO_TYPES_H

#include "mbedtls/build_info.h"

#include "mbedtls/private_access.h"

#if defined(MBEDTLS_PSA_CRYPTO_PLATFORM_FILE)
#include MBEDTLS_PSA_CRYPTO_PLATFORM_FILE
#else
#include "crypto_platform.h"
#endif

#include <stdint.h>

#ifndef PSA_SUCCESS
typedef int32_t psa_status_t;
#endif

typedef uint16_t psa_key_type_t;

typedef uint8_t psa_ecc_family_t;

typedef uint8_t psa_dh_family_t;

typedef uint32_t psa_algorithm_t;

typedef uint32_t psa_key_lifetime_t;

typedef uint8_t psa_key_persistence_t;

typedef uint32_t psa_key_location_t;

typedef uint32_t psa_key_id_t;

#if !defined(MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER)
typedef psa_key_id_t mbedtls_svc_key_id_t;

#else /* MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */

typedef struct {
    psa_key_id_t MBEDTLS_PRIVATE(key_id);
    mbedtls_key_owner_id_t MBEDTLS_PRIVATE(owner);
} mbedtls_svc_key_id_t;

#endif /* !MBEDTLS_PSA_CRYPTO_KEY_ID_ENCODES_OWNER */

typedef uint32_t psa_key_usage_t;

typedef struct psa_key_attributes_s psa_key_attributes_t;


#ifndef __DOXYGEN_ONLY__
#if defined(MBEDTLS_PSA_CRYPTO_SE_C)

typedef uint64_t psa_key_slot_number_t;
#endif /* MBEDTLS_PSA_CRYPTO_SE_C */
#endif /* !__DOXYGEN_ONLY__ */

typedef uint16_t psa_key_derivation_step_t;

#endif /* PSA_CRYPTO_TYPES_H */
