/**
 * \file entropy.h
 *
 * \brief Entropy accumulator implementation
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
#ifndef MBEDTLS_ENTROPY_H
#define MBEDTLS_ENTROPY_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>

#if defined(MBEDTLS_SHA512_C) && !defined(MBEDTLS_ENTROPY_FORCE_SHA256)
#include "mbedtls/sha512.h"
#define MBEDTLS_ENTROPY_SHA512_ACCUMULATOR
#else
#if defined(MBEDTLS_SHA256_C)
#define MBEDTLS_ENTROPY_SHA256_ACCUMULATOR
#include "mbedtls/sha256.h"
#endif
#endif

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#define MBEDTLS_ERR_ENTROPY_SOURCE_FAILED                 -0x003C

#define MBEDTLS_ERR_ENTROPY_MAX_SOURCES                   -0x003E

#define MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED            -0x0040

#define MBEDTLS_ERR_ENTROPY_NO_STRONG_SOURCE              -0x003D

#define MBEDTLS_ERR_ENTROPY_FILE_IO_ERROR                 -0x003F

#if !defined(MBEDTLS_ENTROPY_MAX_SOURCES)
#define MBEDTLS_ENTROPY_MAX_SOURCES     20
#endif

#if !defined(MBEDTLS_ENTROPY_MAX_GATHER)
#define MBEDTLS_ENTROPY_MAX_GATHER      128
#endif

#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
#define MBEDTLS_ENTROPY_BLOCK_SIZE      64
#else
#define MBEDTLS_ENTROPY_BLOCK_SIZE      32
#endif

#define MBEDTLS_ENTROPY_MAX_SEED_SIZE   1024
#define MBEDTLS_ENTROPY_SOURCE_MANUAL   MBEDTLS_ENTROPY_MAX_SOURCES

#define MBEDTLS_ENTROPY_SOURCE_STRONG   1
#define MBEDTLS_ENTROPY_SOURCE_WEAK     0

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*mbedtls_entropy_f_source_ptr)(void *data, unsigned char *output, size_t len,
                                            size_t *olen);

typedef struct mbedtls_entropy_source_state {
    mbedtls_entropy_f_source_ptr    MBEDTLS_PRIVATE(f_source);
    void *MBEDTLS_PRIVATE(p_source);
    size_t          MBEDTLS_PRIVATE(size);
    size_t          MBEDTLS_PRIVATE(threshold);
    int             MBEDTLS_PRIVATE(strong);
}
mbedtls_entropy_source_state;

typedef struct mbedtls_entropy_context {
    int MBEDTLS_PRIVATE(accumulator_started);
#if defined(MBEDTLS_ENTROPY_SHA512_ACCUMULATOR)
    mbedtls_sha512_context  MBEDTLS_PRIVATE(accumulator);
#elif defined(MBEDTLS_ENTROPY_SHA256_ACCUMULATOR)
    mbedtls_sha256_context  MBEDTLS_PRIVATE(accumulator);
#endif
    int             MBEDTLS_PRIVATE(source_count);
    mbedtls_entropy_source_state    MBEDTLS_PRIVATE(source)[MBEDTLS_ENTROPY_MAX_SOURCES];
#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
#if defined(MBEDTLS_ENTROPY_NV_SEED)
    int MBEDTLS_PRIVATE(initial_entropy_run);
#endif
}
mbedtls_entropy_context;

#if !defined(MBEDTLS_NO_PLATFORM_ENTROPY)

int mbedtls_platform_entropy_poll(void *data,
                                  unsigned char *output, size_t len, size_t *olen);
#endif

void mbedtls_entropy_init(mbedtls_entropy_context *ctx);

void mbedtls_entropy_free(mbedtls_entropy_context *ctx);

int mbedtls_entropy_add_source(mbedtls_entropy_context *ctx,
                               mbedtls_entropy_f_source_ptr f_source, void *p_source,
                               size_t threshold, int strong);

int mbedtls_entropy_gather(mbedtls_entropy_context *ctx);

int mbedtls_entropy_func(void *data, unsigned char *output, size_t len);

int mbedtls_entropy_update_manual(mbedtls_entropy_context *ctx,
                                  const unsigned char *data, size_t len);

#if defined(MBEDTLS_ENTROPY_NV_SEED)

int mbedtls_entropy_update_nv_seed(mbedtls_entropy_context *ctx);
#endif /* MBEDTLS_ENTROPY_NV_SEED */

#if defined(MBEDTLS_FS_IO)

int mbedtls_entropy_write_seed_file(mbedtls_entropy_context *ctx, const char *path);

int mbedtls_entropy_update_seed_file(mbedtls_entropy_context *ctx, const char *path);
#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* entropy.h */
