/**
 * \file sha512.h
 * \brief This file contains SHA-384 and SHA-512 definitions and functions.
 *
 * The Secure Hash Algorithms 384 and 512 (SHA-384 and SHA-512) cryptographic
 * hash functions are defined in <em>FIPS 180-4: Secure Hash Standard (SHS)</em>.
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
#ifndef MBEDTLS_SHA512_H
#define MBEDTLS_SHA512_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_SHA512_BAD_INPUT_DATA                 -0x0075

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_SHA512_ALT)

typedef struct mbedtls_sha512_context {
    uint64_t MBEDTLS_PRIVATE(total)[2];
    uint64_t MBEDTLS_PRIVATE(state)[8];
    unsigned char MBEDTLS_PRIVATE(buffer)[128];
#if defined(MBEDTLS_SHA384_C)
    int MBEDTLS_PRIVATE(is384);
#endif
}
mbedtls_sha512_context;

#else  /* MBEDTLS_SHA512_ALT */
#include "sha512_alt.h"
#endif /* MBEDTLS_SHA512_ALT */

void mbedtls_sha512_init(mbedtls_sha512_context *ctx);

void mbedtls_sha512_free(mbedtls_sha512_context *ctx);

void mbedtls_sha512_clone(mbedtls_sha512_context *dst,
                          const mbedtls_sha512_context *src);

int mbedtls_sha512_starts(mbedtls_sha512_context *ctx, int is384);

int mbedtls_sha512_update(mbedtls_sha512_context *ctx,
                          const unsigned char *input,
                          size_t ilen);

int mbedtls_sha512_finish(mbedtls_sha512_context *ctx,
                          unsigned char *output);

int mbedtls_internal_sha512_process(mbedtls_sha512_context *ctx,
                                    const unsigned char data[128]);

int mbedtls_sha512(const unsigned char *input,
                   size_t ilen,
                   unsigned char *output,
                   int is384);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_sha512.h */
