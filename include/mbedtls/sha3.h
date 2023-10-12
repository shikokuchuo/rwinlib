/**
 * \file sha3.h
 *
 * \brief This file contains SHA-3 definitions and functions.
 *
 * The Secure Hash Algorithms cryptographic
 * hash functions are defined in <em>FIPS 202: SHA-3 Standard:
 * Permutation-Based Hash and Extendable-Output Functions </em>.
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

#ifndef MBEDTLS_SHA3_H
#define MBEDTLS_SHA3_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_ERR_SHA3_BAD_INPUT_DATA                 -0x0076

typedef enum {
    MBEDTLS_SHA3_NONE = 0,
    MBEDTLS_SHA3_224,
    MBEDTLS_SHA3_256,
    MBEDTLS_SHA3_384,
    MBEDTLS_SHA3_512,
} mbedtls_sha3_id;

typedef struct {
    uint64_t MBEDTLS_PRIVATE(state[25]);
    uint32_t MBEDTLS_PRIVATE(index);
    uint16_t MBEDTLS_PRIVATE(olen);
    uint16_t MBEDTLS_PRIVATE(max_block_size);
}
mbedtls_sha3_context;

void mbedtls_sha3_init(mbedtls_sha3_context *ctx);

void mbedtls_sha3_free(mbedtls_sha3_context *ctx);

void mbedtls_sha3_clone(mbedtls_sha3_context *dst,
                        const mbedtls_sha3_context *src);

int mbedtls_sha3_starts(mbedtls_sha3_context *ctx, mbedtls_sha3_id id);

int mbedtls_sha3_update(mbedtls_sha3_context *ctx,
                        const uint8_t *input,
                        size_t ilen);

int mbedtls_sha3_finish(mbedtls_sha3_context *ctx,
                        uint8_t *output, size_t olen);

int mbedtls_sha3(mbedtls_sha3_id id, const uint8_t *input,
                 size_t ilen,
                 uint8_t *output,
                 size_t olen);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha3.h */
