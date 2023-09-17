/**
 * \file poly1305.h
 *
 * \brief   This file contains Poly1305 definitions and functions.
 *
 *          Poly1305 is a one-time message authenticator that can be used to
 *          authenticate messages. Poly1305-AES was created by Daniel
 *          Bernstein https://cr.yp.to/mac/poly1305-20050329.pdf The generic
 *          Poly1305 algorithm (not tied to AES) was also standardized in RFC
 *          7539.
 *
 * \author Daniel King <damaki.gh@gmail.com>
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

#ifndef MBEDTLS_POLY1305_H
#define MBEDTLS_POLY1305_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stdint.h>
#include <stddef.h>

#define MBEDTLS_ERR_POLY1305_BAD_INPUT_DATA         -0x0057

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(MBEDTLS_POLY1305_ALT)

typedef struct mbedtls_poly1305_context {
    uint32_t MBEDTLS_PRIVATE(r)[4];
    uint32_t MBEDTLS_PRIVATE(s)[4];
    uint32_t MBEDTLS_PRIVATE(acc)[5];
    uint8_t MBEDTLS_PRIVATE(queue)[16];
    size_t MBEDTLS_PRIVATE(queue_len);
}
mbedtls_poly1305_context;

#else  /* MBEDTLS_POLY1305_ALT */
#include "poly1305_alt.h"
#endif /* MBEDTLS_POLY1305_ALT */

void mbedtls_poly1305_init(mbedtls_poly1305_context *ctx);

void mbedtls_poly1305_free(mbedtls_poly1305_context *ctx);

int mbedtls_poly1305_starts(mbedtls_poly1305_context *ctx,
                            const unsigned char key[32]);

int mbedtls_poly1305_update(mbedtls_poly1305_context *ctx,
                            const unsigned char *input,
                            size_t ilen);

int mbedtls_poly1305_finish(mbedtls_poly1305_context *ctx,
                            unsigned char mac[16]);

int mbedtls_poly1305_mac(const unsigned char key[32],
                         const unsigned char *input,
                         size_t ilen,
                         unsigned char mac[16]);

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_POLY1305_H */
