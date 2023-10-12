/**
 * \file debug.h
 *
 * \brief Functions for controlling and providing debug output from the library.
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
#ifndef MBEDTLS_DEBUG_H
#define MBEDTLS_DEBUG_H

#include "mbedtls/build_info.h"

#include "mbedtls/ssl.h"

#if defined(MBEDTLS_ECP_C)
#include "mbedtls/ecp.h"
#endif

#if defined(MBEDTLS_DEBUG_C)

#define MBEDTLS_DEBUG_STRIP_PARENS(...)   __VA_ARGS__

#define MBEDTLS_SSL_DEBUG_MSG(level, args)                    \
    mbedtls_debug_print_msg(ssl, level, __FILE__, __LINE__,    \
                            MBEDTLS_DEBUG_STRIP_PARENS args)

#define MBEDTLS_SSL_DEBUG_RET(level, text, ret)                \
    mbedtls_debug_print_ret(ssl, level, __FILE__, __LINE__, text, ret)

#define MBEDTLS_SSL_DEBUG_BUF(level, text, buf, len)           \
    mbedtls_debug_print_buf(ssl, level, __FILE__, __LINE__, text, buf, len)

#if defined(MBEDTLS_BIGNUM_C)
#define MBEDTLS_SSL_DEBUG_MPI(level, text, X)                  \
    mbedtls_debug_print_mpi(ssl, level, __FILE__, __LINE__, text, X)
#endif

#if defined(MBEDTLS_ECP_C)
#define MBEDTLS_SSL_DEBUG_ECP(level, text, X)                  \
    mbedtls_debug_print_ecp(ssl, level, __FILE__, __LINE__, text, X)
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C)
#if !defined(MBEDTLS_X509_REMOVE_INFO)
#define MBEDTLS_SSL_DEBUG_CRT(level, text, crt)                \
    mbedtls_debug_print_crt(ssl, level, __FILE__, __LINE__, text, crt)
#else
#define MBEDTLS_SSL_DEBUG_CRT(level, text, crt)       do { } while (0)
#endif /* MBEDTLS_X509_REMOVE_INFO */
#endif /* MBEDTLS_X509_CRT_PARSE_C */

#if defined(MBEDTLS_ECDH_C)
#define MBEDTLS_SSL_DEBUG_ECDH(level, ecdh, attr)               \
    mbedtls_debug_printf_ecdh(ssl, level, __FILE__, __LINE__, ecdh, attr)
#endif

#else /* MBEDTLS_DEBUG_C */

#define MBEDTLS_SSL_DEBUG_MSG(level, args)            do { } while (0)
#define MBEDTLS_SSL_DEBUG_RET(level, text, ret)       do { } while (0)
#define MBEDTLS_SSL_DEBUG_BUF(level, text, buf, len)  do { } while (0)
#define MBEDTLS_SSL_DEBUG_MPI(level, text, X)         do { } while (0)
#define MBEDTLS_SSL_DEBUG_ECP(level, text, X)         do { } while (0)
#define MBEDTLS_SSL_DEBUG_CRT(level, text, crt)       do { } while (0)
#define MBEDTLS_SSL_DEBUG_ECDH(level, ecdh, attr)     do { } while (0)

#endif /* MBEDTLS_DEBUG_C */

#if defined(__has_attribute)
#if __has_attribute(format)
#if defined(__MINGW32__) && __USE_MINGW_ANSI_STDIO == 1
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)    \
    __attribute__((__format__(gnu_printf, string_index, first_to_check)))
#else /* defined(__MINGW32__) && __USE_MINGW_ANSI_STDIO == 1 */
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)    \
    __attribute__((format(printf, string_index, first_to_check)))
#endif
#else /* __has_attribute(format) */
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif /* __has_attribute(format) */
#else /* defined(__has_attribute) */
#define MBEDTLS_PRINTF_ATTRIBUTE(string_index, first_to_check)
#endif

#if (defined(__MINGW32__) && __USE_MINGW_ANSI_STDIO == 0) || (defined(_MSC_VER) && _MSC_VER < 1800)
   #include <inttypes.h>
   #define MBEDTLS_PRINTF_SIZET     PRIuPTR
   #define MBEDTLS_PRINTF_LONGLONG  "I64d"
#else \
    /* (defined(__MINGW32__)  && __USE_MINGW_ANSI_STDIO == 0) || (defined(_MSC_VER) && _MSC_VER < 1800) */
   #define MBEDTLS_PRINTF_SIZET     "zu"
   #define MBEDTLS_PRINTF_LONGLONG  "lld"
#endif \
    /* (defined(__MINGW32__)  && __USE_MINGW_ANSI_STDIO == 0) || (defined(_MSC_VER) && _MSC_VER < 1800) */

#if !defined(MBEDTLS_PRINTF_MS_TIME)
#define MBEDTLS_PRINTF_MS_TIME PRId64
#endif /* MBEDTLS_PRINTF_MS_TIME */

#ifdef __cplusplus
extern "C" {
#endif

void mbedtls_debug_set_threshold(int threshold);

void mbedtls_debug_print_msg(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *format, ...) MBEDTLS_PRINTF_ATTRIBUTE(5, 6);

void mbedtls_debug_print_ret(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, int ret);

void mbedtls_debug_print_buf(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line, const char *text,
                             const unsigned char *buf, size_t len);

#if defined(MBEDTLS_BIGNUM_C)

void mbedtls_debug_print_mpi(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const mbedtls_mpi *X);
#endif

#if defined(MBEDTLS_ECP_C)

void mbedtls_debug_print_ecp(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const mbedtls_ecp_point *X);
#endif

#if defined(MBEDTLS_X509_CRT_PARSE_C) && !defined(MBEDTLS_X509_REMOVE_INFO)

void mbedtls_debug_print_crt(const mbedtls_ssl_context *ssl, int level,
                             const char *file, int line,
                             const char *text, const mbedtls_x509_crt *crt);
#endif

#if defined(MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED) && \
    defined(MBEDTLS_ECDH_C)
typedef enum {
    MBEDTLS_DEBUG_ECDH_Q,
    MBEDTLS_DEBUG_ECDH_QP,
    MBEDTLS_DEBUG_ECDH_Z,
} mbedtls_debug_ecdh_attr;

void mbedtls_debug_printf_ecdh(const mbedtls_ssl_context *ssl, int level,
                               const char *file, int line,
                               const mbedtls_ecdh_context *ecdh,
                               mbedtls_debug_ecdh_attr attr);
#endif /* MBEDTLS_KEY_EXCHANGE_SOME_ECDH_OR_ECDHE_ANY_ENABLED &&
          MBEDTLS_ECDH_C */

#ifdef __cplusplus
}
#endif

#endif /* debug.h */
