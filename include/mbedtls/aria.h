/**
 * \file aria.h
 *
 * \brief ARIA block cipher
 *
 *        The ARIA algorithm is a symmetric block cipher that can encrypt and
 *        decrypt information. It is defined by the Korean Agency for
 *        Technology and Standards (KATS) in <em>KS X 1213:2004</em> (in
 *        Korean, but see http://210.104.33.10/ARIA/index-e.html in English)
 *        and also described by the IETF in <em>RFC 5794</em>.
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

#ifndef MBEDTLS_ARIA_H
#define MBEDTLS_ARIA_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/platform_util.h"

#define MBEDTLS_ARIA_ENCRYPT     1
#define MBEDTLS_ARIA_DECRYPT     0

#define MBEDTLS_ARIA_BLOCKSIZE   16
#define MBEDTLS_ARIA_MAX_ROUNDS  16
#define MBEDTLS_ARIA_MAX_KEYSIZE 32

#define MBEDTLS_ERR_ARIA_BAD_INPUT_DATA -0x005C

#define MBEDTLS_ERR_ARIA_INVALID_INPUT_LENGTH -0x005E

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_ARIA_ALT)

typedef struct mbedtls_aria_context {
    unsigned char MBEDTLS_PRIVATE(nr);
    uint32_t MBEDTLS_PRIVATE(rk)[MBEDTLS_ARIA_MAX_ROUNDS + 1][MBEDTLS_ARIA_BLOCKSIZE / 4];
}
mbedtls_aria_context;

#else  /* MBEDTLS_ARIA_ALT */
#include "aria_alt.h"
#endif /* MBEDTLS_ARIA_ALT */

void mbedtls_aria_init(mbedtls_aria_context *ctx);

void mbedtls_aria_free(mbedtls_aria_context *ctx);

int mbedtls_aria_setkey_enc(mbedtls_aria_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits);

int mbedtls_aria_setkey_dec(mbedtls_aria_context *ctx,
                            const unsigned char *key,
                            unsigned int keybits);

int mbedtls_aria_crypt_ecb(mbedtls_aria_context *ctx,
                           const unsigned char input[MBEDTLS_ARIA_BLOCKSIZE],
                           unsigned char output[MBEDTLS_ARIA_BLOCKSIZE]);

#if defined(MBEDTLS_CIPHER_MODE_CBC)

int mbedtls_aria_crypt_cbc(mbedtls_aria_context *ctx,
                           int mode,
                           size_t length,
                           unsigned char iv[MBEDTLS_ARIA_BLOCKSIZE],
                           const unsigned char *input,
                           unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)

int mbedtls_aria_crypt_cfb128(mbedtls_aria_context *ctx,
                              int mode,
                              size_t length,
                              size_t *iv_off,
                              unsigned char iv[MBEDTLS_ARIA_BLOCKSIZE],
                              const unsigned char *input,
                              unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)

int mbedtls_aria_crypt_ctr(mbedtls_aria_context *ctx,
                           size_t length,
                           size_t *nc_off,
                           unsigned char nonce_counter[MBEDTLS_ARIA_BLOCKSIZE],
                           unsigned char stream_block[MBEDTLS_ARIA_BLOCKSIZE],
                           const unsigned char *input,
                           unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#endif /* aria.h */
