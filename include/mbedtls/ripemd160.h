/**
 * \file ripemd160.h
 *
 * \brief RIPE MD-160 message digest
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
#ifndef MBEDTLS_RIPEMD160_H
#define MBEDTLS_RIPEMD160_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_RIPEMD160_ALT)

typedef struct mbedtls_ripemd160_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];
    uint32_t MBEDTLS_PRIVATE(state)[5];
    unsigned char MBEDTLS_PRIVATE(buffer)[64];
}
mbedtls_ripemd160_context;

#else  /* MBEDTLS_RIPEMD160_ALT */
#include "ripemd160_alt.h"
#endif /* MBEDTLS_RIPEMD160_ALT */

void mbedtls_ripemd160_init(mbedtls_ripemd160_context *ctx);

void mbedtls_ripemd160_free(mbedtls_ripemd160_context *ctx);

void mbedtls_ripemd160_clone(mbedtls_ripemd160_context *dst,
                             const mbedtls_ripemd160_context *src);

int mbedtls_ripemd160_starts(mbedtls_ripemd160_context *ctx);

int mbedtls_ripemd160_update(mbedtls_ripemd160_context *ctx,
                             const unsigned char *input,
                             size_t ilen);

int mbedtls_ripemd160_finish(mbedtls_ripemd160_context *ctx,
                             unsigned char output[20]);

int mbedtls_internal_ripemd160_process(mbedtls_ripemd160_context *ctx,
                                       const unsigned char data[64]);

int mbedtls_ripemd160(const unsigned char *input,
                      size_t ilen,
                      unsigned char output[20]);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_ripemd160.h */
