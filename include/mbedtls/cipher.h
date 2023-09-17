/**
 * \file cipher.h
 *
 * \brief This file contains an abstraction interface for use with the cipher
 * primitives provided by the library. It provides a common interface to all of
 * the available cipher operations.
 *
 * \author Adriaan de Jong <dejong@fox-it.com>
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

#ifndef MBEDTLS_CIPHER_H
#define MBEDTLS_CIPHER_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stddef.h>
#include "mbedtls/platform_util.h"

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CCM_C) || defined(MBEDTLS_CHACHAPOLY_C)
#define MBEDTLS_CIPHER_MODE_AEAD
#endif

#if defined(MBEDTLS_CIPHER_MODE_CBC)
#define MBEDTLS_CIPHER_MODE_WITH_PADDING
#endif

#if defined(MBEDTLS_CIPHER_NULL_CIPHER) || \
    defined(MBEDTLS_CHACHA20_C)
#define MBEDTLS_CIPHER_MODE_STREAM
#endif

#define MBEDTLS_ERR_CIPHER_FEATURE_UNAVAILABLE  -0x6080

#define MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA       -0x6100

#define MBEDTLS_ERR_CIPHER_ALLOC_FAILED         -0x6180

#define MBEDTLS_ERR_CIPHER_INVALID_PADDING      -0x6200

#define MBEDTLS_ERR_CIPHER_FULL_BLOCK_EXPECTED  -0x6280

#define MBEDTLS_ERR_CIPHER_AUTH_FAILED          -0x6300

#define MBEDTLS_ERR_CIPHER_INVALID_CONTEXT      -0x6380

#define MBEDTLS_CIPHER_VARIABLE_IV_LEN     0x01
#define MBEDTLS_CIPHER_VARIABLE_KEY_LEN    0x02

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    MBEDTLS_CIPHER_ID_NONE = 0,
    MBEDTLS_CIPHER_ID_NULL,
    MBEDTLS_CIPHER_ID_AES,
    MBEDTLS_CIPHER_ID_DES,
    MBEDTLS_CIPHER_ID_3DES,
    MBEDTLS_CIPHER_ID_CAMELLIA,
    MBEDTLS_CIPHER_ID_ARIA,
    MBEDTLS_CIPHER_ID_CHACHA20,
} mbedtls_cipher_id_t;

typedef enum {
    MBEDTLS_CIPHER_NONE = 0,
    MBEDTLS_CIPHER_NULL,
    MBEDTLS_CIPHER_AES_128_ECB,
    MBEDTLS_CIPHER_AES_192_ECB,
    MBEDTLS_CIPHER_AES_256_ECB,
    MBEDTLS_CIPHER_AES_128_CBC,
    MBEDTLS_CIPHER_AES_192_CBC,
    MBEDTLS_CIPHER_AES_256_CBC,
    MBEDTLS_CIPHER_AES_128_CFB128,
    MBEDTLS_CIPHER_AES_192_CFB128,
    MBEDTLS_CIPHER_AES_256_CFB128,
    MBEDTLS_CIPHER_AES_128_CTR,
    MBEDTLS_CIPHER_AES_192_CTR,
    MBEDTLS_CIPHER_AES_256_CTR,
    MBEDTLS_CIPHER_AES_128_GCM,
    MBEDTLS_CIPHER_AES_192_GCM,
    MBEDTLS_CIPHER_AES_256_GCM,
    MBEDTLS_CIPHER_CAMELLIA_128_ECB,
    MBEDTLS_CIPHER_CAMELLIA_192_ECB,
    MBEDTLS_CIPHER_CAMELLIA_256_ECB,
    MBEDTLS_CIPHER_CAMELLIA_128_CBC,
    MBEDTLS_CIPHER_CAMELLIA_192_CBC,
    MBEDTLS_CIPHER_CAMELLIA_256_CBC,
    MBEDTLS_CIPHER_CAMELLIA_128_CFB128,
    MBEDTLS_CIPHER_CAMELLIA_192_CFB128,
    MBEDTLS_CIPHER_CAMELLIA_256_CFB128,
    MBEDTLS_CIPHER_CAMELLIA_128_CTR,
    MBEDTLS_CIPHER_CAMELLIA_192_CTR,
    MBEDTLS_CIPHER_CAMELLIA_256_CTR,
    MBEDTLS_CIPHER_CAMELLIA_128_GCM,
    MBEDTLS_CIPHER_CAMELLIA_192_GCM,
    MBEDTLS_CIPHER_CAMELLIA_256_GCM,
    MBEDTLS_CIPHER_DES_ECB,
    MBEDTLS_CIPHER_DES_CBC,
    MBEDTLS_CIPHER_DES_EDE_ECB,
    MBEDTLS_CIPHER_DES_EDE_CBC,
    MBEDTLS_CIPHER_DES_EDE3_ECB,
    MBEDTLS_CIPHER_DES_EDE3_CBC,
    MBEDTLS_CIPHER_AES_128_CCM,
    MBEDTLS_CIPHER_AES_192_CCM,
    MBEDTLS_CIPHER_AES_256_CCM,
    MBEDTLS_CIPHER_AES_128_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_AES_192_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_AES_256_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_CAMELLIA_128_CCM,
    MBEDTLS_CIPHER_CAMELLIA_192_CCM,
    MBEDTLS_CIPHER_CAMELLIA_256_CCM,
    MBEDTLS_CIPHER_CAMELLIA_128_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_CAMELLIA_192_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_CAMELLIA_256_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_ARIA_128_ECB,
    MBEDTLS_CIPHER_ARIA_192_ECB,
    MBEDTLS_CIPHER_ARIA_256_ECB,
    MBEDTLS_CIPHER_ARIA_128_CBC,
    MBEDTLS_CIPHER_ARIA_192_CBC,
    MBEDTLS_CIPHER_ARIA_256_CBC,
    MBEDTLS_CIPHER_ARIA_128_CFB128,
    MBEDTLS_CIPHER_ARIA_192_CFB128,
    MBEDTLS_CIPHER_ARIA_256_CFB128,
    MBEDTLS_CIPHER_ARIA_128_CTR,
    MBEDTLS_CIPHER_ARIA_192_CTR,
    MBEDTLS_CIPHER_ARIA_256_CTR,
    MBEDTLS_CIPHER_ARIA_128_GCM,
    MBEDTLS_CIPHER_ARIA_192_GCM,
    MBEDTLS_CIPHER_ARIA_256_GCM,
    MBEDTLS_CIPHER_ARIA_128_CCM,
    MBEDTLS_CIPHER_ARIA_192_CCM,
    MBEDTLS_CIPHER_ARIA_256_CCM,
    MBEDTLS_CIPHER_ARIA_128_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_ARIA_192_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_ARIA_256_CCM_STAR_NO_TAG,
    MBEDTLS_CIPHER_AES_128_OFB,
    MBEDTLS_CIPHER_AES_192_OFB,
    MBEDTLS_CIPHER_AES_256_OFB,
    MBEDTLS_CIPHER_AES_128_XTS,
    MBEDTLS_CIPHER_AES_256_XTS,
    MBEDTLS_CIPHER_CHACHA20,
    MBEDTLS_CIPHER_CHACHA20_POLY1305,
    MBEDTLS_CIPHER_AES_128_KW,
    MBEDTLS_CIPHER_AES_192_KW,
    MBEDTLS_CIPHER_AES_256_KW,
    MBEDTLS_CIPHER_AES_128_KWP,
    MBEDTLS_CIPHER_AES_192_KWP,
    MBEDTLS_CIPHER_AES_256_KWP,
} mbedtls_cipher_type_t;

typedef enum {
    MBEDTLS_MODE_NONE = 0,
    MBEDTLS_MODE_ECB,
    MBEDTLS_MODE_CBC,
    MBEDTLS_MODE_CFB,
    MBEDTLS_MODE_OFB,
    MBEDTLS_MODE_CTR,
    MBEDTLS_MODE_GCM,
    MBEDTLS_MODE_STREAM,
    MBEDTLS_MODE_CCM,
    MBEDTLS_MODE_CCM_STAR_NO_TAG,
    MBEDTLS_MODE_XTS,
    MBEDTLS_MODE_CHACHAPOLY,
    MBEDTLS_MODE_KW,
    MBEDTLS_MODE_KWP,
} mbedtls_cipher_mode_t;

typedef enum {
    MBEDTLS_PADDING_PKCS7 = 0,
    MBEDTLS_PADDING_ONE_AND_ZEROS,
    MBEDTLS_PADDING_ZEROS_AND_LEN,
    MBEDTLS_PADDING_ZEROS,
    MBEDTLS_PADDING_NONE,
} mbedtls_cipher_padding_t;

typedef enum {
    MBEDTLS_OPERATION_NONE = -1,
    MBEDTLS_DECRYPT = 0,
    MBEDTLS_ENCRYPT,
} mbedtls_operation_t;

enum {
    MBEDTLS_KEY_LENGTH_NONE = 0,
    MBEDTLS_KEY_LENGTH_DES  = 64,
    MBEDTLS_KEY_LENGTH_DES_EDE = 128,
    MBEDTLS_KEY_LENGTH_DES_EDE3 = 192,
};

#define MBEDTLS_MAX_IV_LENGTH      16

#define MBEDTLS_MAX_BLOCK_LENGTH   16

#if defined(MBEDTLS_CIPHER_MODE_XTS)
#define MBEDTLS_MAX_KEY_LENGTH     64
#else
#define MBEDTLS_MAX_KEY_LENGTH     32
#endif /* MBEDTLS_CIPHER_MODE_XTS */

typedef struct mbedtls_cipher_base_t mbedtls_cipher_base_t;

typedef struct mbedtls_cmac_context_t mbedtls_cmac_context_t;

typedef struct mbedtls_cipher_info_t {
    mbedtls_cipher_type_t MBEDTLS_PRIVATE(type);
    mbedtls_cipher_mode_t MBEDTLS_PRIVATE(mode);
    unsigned int MBEDTLS_PRIVATE(key_bitlen);
    const char *MBEDTLS_PRIVATE(name);
    unsigned int MBEDTLS_PRIVATE(iv_size);
    int MBEDTLS_PRIVATE(flags);
    unsigned int MBEDTLS_PRIVATE(block_size);
    const mbedtls_cipher_base_t *MBEDTLS_PRIVATE(base);

} mbedtls_cipher_info_t;

typedef struct mbedtls_cipher_context_t {
    const mbedtls_cipher_info_t *MBEDTLS_PRIVATE(cipher_info);
    int MBEDTLS_PRIVATE(key_bitlen);
    mbedtls_operation_t MBEDTLS_PRIVATE(operation);

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)
    void(*MBEDTLS_PRIVATE(add_padding))(unsigned char *output, size_t olen, size_t data_len);
    int(*MBEDTLS_PRIVATE(get_padding))(unsigned char *input, size_t ilen, size_t *data_len);
#endif

    unsigned char MBEDTLS_PRIVATE(unprocessed_data)[MBEDTLS_MAX_BLOCK_LENGTH];

    size_t MBEDTLS_PRIVATE(unprocessed_len);

    unsigned char MBEDTLS_PRIVATE(iv)[MBEDTLS_MAX_IV_LENGTH];

    size_t MBEDTLS_PRIVATE(iv_size);

    void *MBEDTLS_PRIVATE(cipher_ctx);

#if defined(MBEDTLS_CMAC_C)
    mbedtls_cmac_context_t *MBEDTLS_PRIVATE(cmac_ctx);
#endif

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    unsigned char MBEDTLS_PRIVATE(psa_enabled);
#endif /* MBEDTLS_USE_PSA_CRYPTO */

} mbedtls_cipher_context_t;

const int *mbedtls_cipher_list(void);

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_string(const char *cipher_name);

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_type(const mbedtls_cipher_type_t cipher_type);

const mbedtls_cipher_info_t *mbedtls_cipher_info_from_values(const mbedtls_cipher_id_t cipher_id,
                                                             int key_bitlen,
                                                             const mbedtls_cipher_mode_t mode);

static inline mbedtls_cipher_type_t mbedtls_cipher_info_get_type(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return MBEDTLS_CIPHER_NONE;
    } else {
        return info->MBEDTLS_PRIVATE(type);
    }
}

static inline mbedtls_cipher_mode_t mbedtls_cipher_info_get_mode(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return MBEDTLS_MODE_NONE;
    } else {
        return info->MBEDTLS_PRIVATE(mode);
    }
}

static inline size_t mbedtls_cipher_info_get_key_bitlen(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    } else {
        return info->MBEDTLS_PRIVATE(key_bitlen);
    }
}

static inline const char *mbedtls_cipher_info_get_name(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return NULL;
    } else {
        return info->MBEDTLS_PRIVATE(name);
    }
}

static inline size_t mbedtls_cipher_info_get_iv_size(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    }

    return (size_t) info->MBEDTLS_PRIVATE(iv_size);
}

static inline size_t mbedtls_cipher_info_get_block_size(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    }

    return (size_t) info->MBEDTLS_PRIVATE(block_size);
}

static inline int mbedtls_cipher_info_has_variable_key_bitlen(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    }

    return info->MBEDTLS_PRIVATE(flags) & MBEDTLS_CIPHER_VARIABLE_KEY_LEN;
}

static inline int mbedtls_cipher_info_has_variable_iv_size(
    const mbedtls_cipher_info_t *info)
{
    if (info == NULL) {
        return 0;
    }

    return info->MBEDTLS_PRIVATE(flags) & MBEDTLS_CIPHER_VARIABLE_IV_LEN;
}

void mbedtls_cipher_init(mbedtls_cipher_context_t *ctx);

void mbedtls_cipher_free(mbedtls_cipher_context_t *ctx);

int mbedtls_cipher_setup(mbedtls_cipher_context_t *ctx,
                         const mbedtls_cipher_info_t *cipher_info);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
#if !defined(MBEDTLS_DEPRECATED_REMOVED)

int MBEDTLS_DEPRECATED mbedtls_cipher_setup_psa(mbedtls_cipher_context_t *ctx,
                                                const mbedtls_cipher_info_t *cipher_info,
                                                size_t taglen);
#endif /* MBEDTLS_DEPRECATED_REMOVED */
#endif /* MBEDTLS_USE_PSA_CRYPTO */

static inline unsigned int mbedtls_cipher_get_block_size(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL, 0);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return 0;
    }

    return ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(block_size);
}

static inline mbedtls_cipher_mode_t mbedtls_cipher_get_cipher_mode(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL, MBEDTLS_MODE_NONE);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return MBEDTLS_MODE_NONE;
    }

    return ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(mode);
}

static inline int mbedtls_cipher_get_iv_size(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL, 0);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return 0;
    }

    if (ctx->MBEDTLS_PRIVATE(iv_size) != 0) {
        return (int) ctx->MBEDTLS_PRIVATE(iv_size);
    }

    return (int) ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(iv_size);
}

static inline mbedtls_cipher_type_t mbedtls_cipher_get_type(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(
        ctx != NULL, MBEDTLS_CIPHER_NONE);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return MBEDTLS_CIPHER_NONE;
    }

    return ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(type);
}

static inline const char *mbedtls_cipher_get_name(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(ctx != NULL, 0);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return 0;
    }

    return ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(name);
}

static inline int mbedtls_cipher_get_key_bitlen(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(
        ctx != NULL, MBEDTLS_KEY_LENGTH_NONE);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return MBEDTLS_KEY_LENGTH_NONE;
    }

    return (int) ctx->MBEDTLS_PRIVATE(cipher_info)->MBEDTLS_PRIVATE(key_bitlen);
}

static inline mbedtls_operation_t mbedtls_cipher_get_operation(
    const mbedtls_cipher_context_t *ctx)
{
    MBEDTLS_INTERNAL_VALIDATE_RET(
        ctx != NULL, MBEDTLS_OPERATION_NONE);
    if (ctx->MBEDTLS_PRIVATE(cipher_info) == NULL) {
        return MBEDTLS_OPERATION_NONE;
    }

    return ctx->MBEDTLS_PRIVATE(operation);
}

int mbedtls_cipher_setkey(mbedtls_cipher_context_t *ctx,
                          const unsigned char *key,
                          int key_bitlen,
                          const mbedtls_operation_t operation);

#if defined(MBEDTLS_CIPHER_MODE_WITH_PADDING)

int mbedtls_cipher_set_padding_mode(mbedtls_cipher_context_t *ctx,
                                    mbedtls_cipher_padding_t mode);
#endif /* MBEDTLS_CIPHER_MODE_WITH_PADDING */

int mbedtls_cipher_set_iv(mbedtls_cipher_context_t *ctx,
                          const unsigned char *iv,
                          size_t iv_len);

int mbedtls_cipher_reset(mbedtls_cipher_context_t *ctx);

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)

int mbedtls_cipher_update_ad(mbedtls_cipher_context_t *ctx,
                             const unsigned char *ad, size_t ad_len);
#endif /* MBEDTLS_GCM_C || MBEDTLS_CHACHAPOLY_C */

int mbedtls_cipher_update(mbedtls_cipher_context_t *ctx,
                          const unsigned char *input,
                          size_t ilen, unsigned char *output,
                          size_t *olen);

int mbedtls_cipher_finish(mbedtls_cipher_context_t *ctx,
                          unsigned char *output, size_t *olen);

#if defined(MBEDTLS_GCM_C) || defined(MBEDTLS_CHACHAPOLY_C)

int mbedtls_cipher_write_tag(mbedtls_cipher_context_t *ctx,
                             unsigned char *tag, size_t tag_len);

int mbedtls_cipher_check_tag(mbedtls_cipher_context_t *ctx,
                             const unsigned char *tag, size_t tag_len);
#endif /* MBEDTLS_GCM_C || MBEDTLS_CHACHAPOLY_C */

int mbedtls_cipher_crypt(mbedtls_cipher_context_t *ctx,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output, size_t *olen);

#if defined(MBEDTLS_CIPHER_MODE_AEAD) || defined(MBEDTLS_NIST_KW_C)

int mbedtls_cipher_auth_encrypt_ext(mbedtls_cipher_context_t *ctx,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ad, size_t ad_len,
                                    const unsigned char *input, size_t ilen,
                                    unsigned char *output, size_t output_len,
                                    size_t *olen, size_t tag_len);

int mbedtls_cipher_auth_decrypt_ext(mbedtls_cipher_context_t *ctx,
                                    const unsigned char *iv, size_t iv_len,
                                    const unsigned char *ad, size_t ad_len,
                                    const unsigned char *input, size_t ilen,
                                    unsigned char *output, size_t output_len,
                                    size_t *olen, size_t tag_len);
#endif /* MBEDTLS_CIPHER_MODE_AEAD || MBEDTLS_NIST_KW_C */
#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_CIPHER_H */
