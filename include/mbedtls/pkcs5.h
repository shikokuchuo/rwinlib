/**
 * \file pkcs5.h
 *
 * \brief PKCS#5 functions
 *
 * \author Mathias Olsson <mathias@kompetensum.com>
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
#ifndef MBEDTLS_PKCS5_H
#define MBEDTLS_PKCS5_H

#include "mbedtls/build_info.h"

#include "mbedtls/asn1.h"
#include "mbedtls/md.h"

#include <stddef.h>
#include <stdint.h>

#define MBEDTLS_ERR_PKCS5_BAD_INPUT_DATA                  -0x2f80

#define MBEDTLS_ERR_PKCS5_INVALID_FORMAT                  -0x2f00

#define MBEDTLS_ERR_PKCS5_FEATURE_UNAVAILABLE             -0x2e80

#define MBEDTLS_ERR_PKCS5_PASSWORD_MISMATCH               -0x2e00

#define MBEDTLS_PKCS5_DECRYPT      0
#define MBEDTLS_PKCS5_ENCRYPT      1

#ifdef __cplusplus
extern "C" {
#endif

#if defined(MBEDTLS_ASN1_PARSE_C)

int mbedtls_pkcs5_pbes2(const mbedtls_asn1_buf *pbe_params, int mode,
                        const unsigned char *pwd,  size_t pwdlen,
                        const unsigned char *data, size_t datalen,
                        unsigned char *output);

#endif /* MBEDTLS_ASN1_PARSE_C */

int mbedtls_pkcs5_pbkdf2_hmac_ext(mbedtls_md_type_t md_type,
                                  const unsigned char *password,
                                  size_t plen, const unsigned char *salt, size_t slen,
                                  unsigned int iteration_count,
                                  uint32_t key_length, unsigned char *output);

#if defined(MBEDTLS_MD_C)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)

int MBEDTLS_DEPRECATED mbedtls_pkcs5_pbkdf2_hmac(mbedtls_md_context_t *ctx,
                                                 const unsigned char *password,
                                                 size_t plen,
                                                 const unsigned char *salt,
                                                 size_t slen,
                                                 unsigned int iteration_count,
                                                 uint32_t key_length,
                                                 unsigned char *output);
#endif /* !MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_MD_C */


#ifdef __cplusplus
}
#endif

#endif /* pkcs5.h */
