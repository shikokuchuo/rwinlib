/**
 * \file md5.h
 *
 * \brief MD5 message digest algorithm (hash function)
 *
 * \warning   MD5 is considered a weak message digest and its use constitutes a
 *            security risk. We recommend considering stronger message
 *            digests instead.
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
#ifndef MBEDTLS_MD5_H
#define MBEDTLS_MD5_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_MD5_ALT)

typedef struct mbedtls_md5_context {
    uint32_t MBEDTLS_PRIVATE(total)[2];
    uint32_t MBEDTLS_PRIVATE(state)[4];
    unsigned char MBEDTLS_PRIVATE(buffer)[64];
}
mbedtls_md5_context;

#else  /* MBEDTLS_MD5_ALT */
#include "md5_alt.h"
#endif /* MBEDTLS_MD5_ALT */

void mbedtls_md5_init(mbedtls_md5_context *ctx);

void mbedtls_md5_free(mbedtls_md5_context *ctx);

void mbedtls_md5_clone(mbedtls_md5_context *dst,
                       const mbedtls_md5_context *src);

int mbedtls_md5_starts(mbedtls_md5_context *ctx);

int mbedtls_md5_update(mbedtls_md5_context *ctx,
                       const unsigned char *input,
                       size_t ilen);

int mbedtls_md5_finish(mbedtls_md5_context *ctx,
                       unsigned char output[16]);

int mbedtls_internal_md5_process(mbedtls_md5_context *ctx,
                                 const unsigned char data[64]);

int mbedtls_md5(const unsigned char *input,
                size_t ilen,
                unsigned char output[16]);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md5.h */
