/**
 * \file x509_crl.h
 *
 * \brief X.509 certificate revocation list parsing
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
#ifndef MBEDTLS_X509_CRL_H
#define MBEDTLS_X509_CRL_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_x509_crl_entry {
    mbedtls_x509_buf raw;
    mbedtls_x509_buf serial;
    mbedtls_x509_time revocation_date;
    mbedtls_x509_buf entry_ext;
    struct mbedtls_x509_crl_entry *next;
}
mbedtls_x509_crl_entry;

typedef struct mbedtls_x509_crl {
    mbedtls_x509_buf raw;
    mbedtls_x509_buf tbs;

    int version;
    mbedtls_x509_buf sig_oid;

    mbedtls_x509_buf issuer_raw;

    mbedtls_x509_name issuer;

    mbedtls_x509_time this_update;
    mbedtls_x509_time next_update;

    mbedtls_x509_crl_entry entry;

    mbedtls_x509_buf crl_ext;

    mbedtls_x509_buf MBEDTLS_PRIVATE(sig_oid2);
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);
    void *MBEDTLS_PRIVATE(sig_opts);

    struct mbedtls_x509_crl *next;
}
mbedtls_x509_crl;

int mbedtls_x509_crl_parse_der(mbedtls_x509_crl *chain,
                               const unsigned char *buf, size_t buflen);

int mbedtls_x509_crl_parse(mbedtls_x509_crl *chain, const unsigned char *buf, size_t buflen);

#if defined(MBEDTLS_FS_IO)

int mbedtls_x509_crl_parse_file(mbedtls_x509_crl *chain, const char *path);
#endif /* MBEDTLS_FS_IO */

#if !defined(MBEDTLS_X509_REMOVE_INFO)

int mbedtls_x509_crl_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_crl *crl);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

void mbedtls_x509_crl_init(mbedtls_x509_crl *crl);

void mbedtls_x509_crl_free(mbedtls_x509_crl *crl);

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_x509_crl.h */
