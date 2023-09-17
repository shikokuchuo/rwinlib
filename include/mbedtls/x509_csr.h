/**
 * \file x509_csr.h
 *
 * \brief X.509 certificate signing request parsing and writing
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
#ifndef MBEDTLS_X509_CSR_H
#define MBEDTLS_X509_CSR_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include "mbedtls/x509.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mbedtls_x509_csr {
    mbedtls_x509_buf raw;
    mbedtls_x509_buf cri;

    int version;

    mbedtls_x509_buf  subject_raw;
    mbedtls_x509_name subject;

    mbedtls_pk_context pk;

    unsigned int key_usage;
    unsigned char ns_cert_type;
    mbedtls_x509_sequence subject_alt_names;

    int MBEDTLS_PRIVATE(ext_types);

    mbedtls_x509_buf sig_oid;
    mbedtls_x509_buf MBEDTLS_PRIVATE(sig);
    mbedtls_md_type_t MBEDTLS_PRIVATE(sig_md);
    mbedtls_pk_type_t MBEDTLS_PRIVATE(sig_pk);
    void *MBEDTLS_PRIVATE(sig_opts);
}
mbedtls_x509_csr;

typedef struct mbedtls_x509write_csr {
    mbedtls_pk_context *MBEDTLS_PRIVATE(key);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(subject);
    mbedtls_md_type_t MBEDTLS_PRIVATE(md_alg);
    mbedtls_asn1_named_data *MBEDTLS_PRIVATE(extensions);
}
mbedtls_x509write_csr;

typedef struct mbedtls_x509_san_list {
    mbedtls_x509_subject_alternative_name node;
    struct mbedtls_x509_san_list *next;
}
mbedtls_x509_san_list;

#if defined(MBEDTLS_X509_CSR_PARSE_C)

int mbedtls_x509_csr_parse_der(mbedtls_x509_csr *csr,
                               const unsigned char *buf, size_t buflen);

int mbedtls_x509_csr_parse(mbedtls_x509_csr *csr, const unsigned char *buf, size_t buflen);

#if defined(MBEDTLS_FS_IO)

int mbedtls_x509_csr_parse_file(mbedtls_x509_csr *csr, const char *path);
#endif /* MBEDTLS_FS_IO */

#if !defined(MBEDTLS_X509_REMOVE_INFO)

int mbedtls_x509_csr_info(char *buf, size_t size, const char *prefix,
                          const mbedtls_x509_csr *csr);
#endif /* !MBEDTLS_X509_REMOVE_INFO */

void mbedtls_x509_csr_init(mbedtls_x509_csr *csr);

void mbedtls_x509_csr_free(mbedtls_x509_csr *csr);
#endif /* MBEDTLS_X509_CSR_PARSE_C */

#if defined(MBEDTLS_X509_CSR_WRITE_C)

void mbedtls_x509write_csr_init(mbedtls_x509write_csr *ctx);

int mbedtls_x509write_csr_set_subject_name(mbedtls_x509write_csr *ctx,
                                           const char *subject_name);

void mbedtls_x509write_csr_set_key(mbedtls_x509write_csr *ctx, mbedtls_pk_context *key);

void mbedtls_x509write_csr_set_md_alg(mbedtls_x509write_csr *ctx, mbedtls_md_type_t md_alg);

int mbedtls_x509write_csr_set_key_usage(mbedtls_x509write_csr *ctx, unsigned char key_usage);

int mbedtls_x509write_csr_set_subject_alternative_name(mbedtls_x509write_csr *ctx,
                                                       const mbedtls_x509_san_list *san_list);

int mbedtls_x509write_csr_set_ns_cert_type(mbedtls_x509write_csr *ctx,
                                           unsigned char ns_cert_type);

int mbedtls_x509write_csr_set_extension(mbedtls_x509write_csr *ctx,
                                        const char *oid, size_t oid_len,
                                        int critical,
                                        const unsigned char *val, size_t val_len);

void mbedtls_x509write_csr_free(mbedtls_x509write_csr *ctx);

int mbedtls_x509write_csr_der(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);

#if defined(MBEDTLS_PEM_WRITE_C)

int mbedtls_x509write_csr_pem(mbedtls_x509write_csr *ctx, unsigned char *buf, size_t size,
                              int (*f_rng)(void *, unsigned char *, size_t),
                              void *p_rng);
#endif /* MBEDTLS_PEM_WRITE_C */
#endif /* MBEDTLS_X509_CSR_WRITE_C */

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_x509_csr.h */
