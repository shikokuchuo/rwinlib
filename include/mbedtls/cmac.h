/**
 * \file cmac.h
 *
 * \brief This file contains CMAC definitions and functions.
 *
 * The Cipher-based Message Authentication Code (CMAC) Mode for
 * Authentication is defined in <em>RFC-4493: The AES-CMAC Algorithm</em>.
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

#ifndef MBEDTLS_CMAC_H
#define MBEDTLS_CMAC_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/cipher.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_AES_BLOCK_SIZE          16
#define MBEDTLS_DES3_BLOCK_SIZE         8

#if defined(MBEDTLS_AES_C)
#define MBEDTLS_CIPHER_BLKSIZE_MAX      16
#else
#define MBEDTLS_CIPHER_BLKSIZE_MAX      8
#endif

#if !defined(MBEDTLS_CMAC_ALT)

struct mbedtls_cmac_context_t {
    unsigned char       MBEDTLS_PRIVATE(state)[MBEDTLS_CIPHER_BLKSIZE_MAX];
    unsigned char       MBEDTLS_PRIVATE(unprocessed_block)[MBEDTLS_CIPHER_BLKSIZE_MAX];
    size_t              MBEDTLS_PRIVATE(unprocessed_len);
};

#else  /* !MBEDTLS_CMAC_ALT */
#include "cmac_alt.h"
#endif /* !MBEDTLS_CMAC_ALT */

int mbedtls_cipher_cmac_starts(mbedtls_cipher_context_t *ctx,
                               const unsigned char *key, size_t keybits);

int mbedtls_cipher_cmac_update(mbedtls_cipher_context_t *ctx,
                               const unsigned char *input, size_t ilen);

int mbedtls_cipher_cmac_finish(mbedtls_cipher_context_t *ctx,
                               unsigned char *output);

int mbedtls_cipher_cmac_reset(mbedtls_cipher_context_t *ctx);

int mbedtls_cipher_cmac(const mbedtls_cipher_info_t *cipher_info,
                        const unsigned char *key, size_t keylen,
                        const unsigned char *input, size_t ilen,
                        unsigned char *output);

#if defined(MBEDTLS_AES_C)

int mbedtls_aes_cmac_prf_128(const unsigned char *key, size_t key_len,
                             const unsigned char *input, size_t in_len,
                             unsigned char output[16]);
#endif /* MBEDTLS_AES_C */

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CMAC_H */
