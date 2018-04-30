/* Copyright (c) 2018 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __SECURE_TIME_CLIENT_PROXY_COMMON_H__
#define __SECURE_TIME_CLIENT_PROXY_COMMON_H__

#include "psa_defs.h"

#define TIME_SET_TRUSTED_INIT_MINOR     1
#define TIME_SET_TRUSTED_COMMIT_MINOR   1
#define TIME_GET_MINOR                  1
#define TIME_SET_MINOR                  1
#define SET_PUBLIC_KEY_MINOR            1
#define GET_PUBLIC_KEY_SIZE_MINOR       1
#define GET_PUBLIC_KEY_MINOR            1

int32_t psa_invoke_sf(
    uint32_t sfid,
    uint32_t minor_version,
    const psa_invec_t *in_vec,
    size_t in_len,
    const psa_outvec_t *out_vec,
    size_t out_len
    );
    
#endif // __SECURE_TIME_CLIENT_PROXY_COMMON_H__