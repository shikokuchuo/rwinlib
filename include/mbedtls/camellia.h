/**
 * \file camellia.h
 *
 * \brief Camellia block cipher
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
#ifndef MBEDTLS_CAMELLIA_H
#define MBEDTLS_CAMELLIA_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include <stdint.h>

#include "mbedtls/platform_util.h"

#define MBEDTLS_CAMELLIA_ENCRYPT     1
#define MBEDTLS_CAMELLIA_DECRYPT     0

#define MBEDTLS_ERR_CAMELLIA_BAD_INPUT_DATA -0x0024

#define MBEDTLS_ERR_CAMELLIA_INVALID_INPUT_LENGTH -0x0026

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_CAMELLIA_ALT)

typedef struct mbedtls_camellia_context {
    int MBEDTLS_PRIVATE(nr);                     /*!<  number of rounds  */
    uint32_t MBEDTLS_PRIVATE(rk)[68];            /*!<  CAMELLIA round keys    */
}
mbedtls_camellia_context;

#else  /* MBEDTLS_CAMELLIA_ALT */
#include "camellia_alt.h"
#endif /* MBEDTLS_CAMELLIA_ALT */

void mbedtls_camellia_init(mbedtls_camellia_context *ctx);

void mbedtls_camellia_free(mbedtls_camellia_context *ctx);

int mbedtls_camellia_setkey_enc(mbedtls_camellia_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits);

int mbedtls_camellia_setkey_dec(mbedtls_camellia_context *ctx,
                                const unsigned char *key,
                                unsigned int keybits);

int mbedtls_camellia_crypt_ecb(mbedtls_camellia_context *ctx,
                               int mode,
                               const unsigned char input[16],
                               unsigned char output[16]);

#if defined(MBEDTLS_CIPHER_MODE_CBC)

int mbedtls_camellia_crypt_cbc(mbedtls_camellia_context *ctx,
                               int mode,
                               size_t length,
                               unsigned char iv[16],
                               const unsigned char *input,
                               unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CBC */

#if defined(MBEDTLS_CIPHER_MODE_CFB)

int mbedtls_camellia_crypt_cfb128(mbedtls_camellia_context *ctx,
                                  int mode,
                                  size_t length,
                                  size_t *iv_off,
                                  unsigned char iv[16],
                                  const unsigned char *input,
                                  unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CFB */

#if defined(MBEDTLS_CIPHER_MODE_CTR)

int mbedtls_camellia_crypt_ctr(mbedtls_camellia_context *ctx,
                               size_t length,
                               size_t *nc_off,
                               unsigned char nonce_counter[16],
                               unsigned char stream_block[16],
                               const unsigned char *input,
                               unsigned char *output);
#endif /* MBEDTLS_CIPHER_MODE_CTR */

#ifdef __cplusplus
}
#endif

#endif /* camellia.h */
