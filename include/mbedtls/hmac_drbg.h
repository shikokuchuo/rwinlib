/**
 * \file hmac_drbg.h
 *
 * \brief The HMAC_DRBG pseudorandom generator.
 *
 * This module implements the HMAC_DRBG pseudorandom generator described
 * in <em>NIST SP 800-90A: Recommendation for Random Number Generation Using
 * Deterministic Random Bit Generators</em>.
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
#ifndef MBEDTLS_HMAC_DRBG_H
#define MBEDTLS_HMAC_DRBG_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/md.h"

#if defined(MBEDTLS_THREADING_C)
#include "mbedtls/threading.h"
#endif

#define MBEDTLS_ERR_HMAC_DRBG_REQUEST_TOO_BIG              -0x0003

#define MBEDTLS_ERR_HMAC_DRBG_INPUT_TOO_BIG                -0x0005

#define MBEDTLS_ERR_HMAC_DRBG_FILE_IO_ERROR                -0x0007

#define MBEDTLS_ERR_HMAC_DRBG_ENTROPY_SOURCE_FAILED        -0x0009

#if !defined(MBEDTLS_HMAC_DRBG_RESEED_INTERVAL)
#define MBEDTLS_HMAC_DRBG_RESEED_INTERVAL   10000   /**< Interval before reseed is performed by default */
#endif

#if !defined(MBEDTLS_HMAC_DRBG_MAX_INPUT)
#define MBEDTLS_HMAC_DRBG_MAX_INPUT         256     /**< Maximum number of additional input bytes */
#endif

#if !defined(MBEDTLS_HMAC_DRBG_MAX_REQUEST)
#define MBEDTLS_HMAC_DRBG_MAX_REQUEST       1024    /**< Maximum number of requested bytes per call */
#endif

#if !defined(MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT)
#define MBEDTLS_HMAC_DRBG_MAX_SEED_INPUT    384     /**< Maximum size of (re)seed buffer */
#endif

#define MBEDTLS_HMAC_DRBG_PR_OFF   0   /**< No prediction resistance       */
#define MBEDTLS_HMAC_DRBG_PR_ON    1   /**< Prediction resistance enabled  */

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_hmac_drbg_context {
    mbedtls_md_context_t MBEDTLS_PRIVATE(md_ctx);                    /*!< HMAC context (inc. K)  */
    unsigned char MBEDTLS_PRIVATE(V)[MBEDTLS_MD_MAX_SIZE];  /*!< V in the spec          */
    int MBEDTLS_PRIVATE(reseed_counter);                     /*!< reseed counter         */

    size_t MBEDTLS_PRIVATE(entropy_len);         /*!< entropy bytes grabbed on each (re)seed */
    int MBEDTLS_PRIVATE(prediction_resistance);  /*!< enable prediction resistance (Automatic
                                                    reseed before every random generation) */
    int MBEDTLS_PRIVATE(reseed_interval);        /*!< reseed interval   */

    int(*MBEDTLS_PRIVATE(f_entropy))(void *, unsigned char *, size_t);  /*!< entropy function */
    void *MBEDTLS_PRIVATE(p_entropy);            /*!< context for the entropy function        */

#if defined(MBEDTLS_THREADING_C)
    mbedtls_threading_mutex_t MBEDTLS_PRIVATE(mutex);
#endif
} mbedtls_hmac_drbg_context;

void mbedtls_hmac_drbg_init(mbedtls_hmac_drbg_context *ctx);

int mbedtls_hmac_drbg_seed(mbedtls_hmac_drbg_context *ctx,
                           const mbedtls_md_info_t *md_info,
                           int (*f_entropy)(void *, unsigned char *, size_t),
                           void *p_entropy,
                           const unsigned char *custom,
                           size_t len);

int mbedtls_hmac_drbg_seed_buf(mbedtls_hmac_drbg_context *ctx,
                               const mbedtls_md_info_t *md_info,
                               const unsigned char *data, size_t data_len);

void mbedtls_hmac_drbg_set_prediction_resistance(mbedtls_hmac_drbg_context *ctx,
                                                 int resistance);

void mbedtls_hmac_drbg_set_entropy_len(mbedtls_hmac_drbg_context *ctx,
                                       size_t len);

void mbedtls_hmac_drbg_set_reseed_interval(mbedtls_hmac_drbg_context *ctx,
                                           int interval);

int mbedtls_hmac_drbg_update(mbedtls_hmac_drbg_context *ctx,
                             const unsigned char *additional, size_t add_len);

int mbedtls_hmac_drbg_reseed(mbedtls_hmac_drbg_context *ctx,
                             const unsigned char *additional, size_t len);

int mbedtls_hmac_drbg_random_with_add(void *p_rng,
                                      unsigned char *output, size_t output_len,
                                      const unsigned char *additional,
                                      size_t add_len);

#if defined(MBEDTLS_THREADING_C)

#endif /* MBEDTLS_THREADING_C */

int mbedtls_hmac_drbg_random(void *p_rng, unsigned char *output, size_t out_len);

void mbedtls_hmac_drbg_free(mbedtls_hmac_drbg_context *ctx);

#if defined(MBEDTLS_FS_IO)

int mbedtls_hmac_drbg_write_seed_file(mbedtls_hmac_drbg_context *ctx, const char *path);

int mbedtls_hmac_drbg_update_seed_file(mbedtls_hmac_drbg_context *ctx, const char *path);
#endif /* MBEDTLS_FS_IO */

#ifdef __cplusplus
}
#endif

#endif /* hmac_drbg.h */
