/**
 * \file timing.h
 *
 * \brief Portable interface to timeouts and to the CPU cycle counter
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
#ifndef MBEDTLS_TIMING_H
#define MBEDTLS_TIMING_H
#include "mbedtls/private_access.h"

#include "mbedtls/build_info.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct mbedtls_timing_hr_time {
    uint64_t MBEDTLS_PRIVATE(opaque)[4];
};

typedef struct mbedtls_timing_delay_context {
    struct mbedtls_timing_hr_time   MBEDTLS_PRIVATE(timer);
    uint32_t                        MBEDTLS_PRIVATE(int_ms);
    uint32_t                        MBEDTLS_PRIVATE(fin_ms);
} mbedtls_timing_delay_context;

unsigned long mbedtls_timing_get_timer(struct mbedtls_timing_hr_time *val, int reset);

void mbedtls_timing_set_delay(void *data, uint32_t int_ms, uint32_t fin_ms);

int mbedtls_timing_get_delay(void *data);

uint32_t mbedtls_timing_get_final_delay(
    const mbedtls_timing_delay_context *data);

#ifdef __cplusplus
}
#endif

#endif /* timing.h */
