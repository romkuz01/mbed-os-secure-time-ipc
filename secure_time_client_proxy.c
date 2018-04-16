#include "psa_defs.h"
#include "spm_client.h"
#include "psa_client_common.h"
#include "secure_time_client_common.h"
#include "secure_time_client.h"
#include "secure_time_client_spe.h"

int32_t secure_time_get_nonce(size_t nonce_size, void *nonce)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {&nonce_size, sizeof(size_t)}
    };
    psa_outvec_t reply_data[2] = {
        {&reply_status, sizeof(int32_t)},
        {nonce, nonce_size}
    };

    if (!psa_invoke_sf(
        GET_NONCE,
        GET_NONCE_MINOR,
        request_data,
        1,
        reply_data,
        2))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

int32_t secure_time_set_trusted(
    const void *blob,
    size_t blob_size,
    const void *sign,
    size_t sign_size
    )
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[2] = {
        {blob, blob_size},
        {sign, sign_size}
    };
    psa_outvec_t reply_data[1] = {
        {&reply_status, sizeof(int32_t)}
    };
    
    if (!psa_invoke_sf(
        TIME_SET_TRUSTED,
        TIME_SET_TRUSTED_MINOR,
        request_data,
        2,
        reply_data,
        1))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

int32_t secure_time_set(uint64_t new_time)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {&new_time, sizeof(uint64_t)}
    };
    psa_outvec_t reply_data[1] = {
        {&reply_status, sizeof(int32_t)}
    };
    
    if (!psa_invoke_sf(
        TIME_SET,
        TIME_SET_MINOR,
        request_data,
        1,
        reply_data,
        1))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

uint64_t secure_time_get(void)
{
    uint64_t time = 0;
    psa_outvec_t reply_data[1] = {
        {&time, sizeof(uint64_t)}
    };

    if (!psa_invoke_sf(
        TIME_GET,
        TIME_GET_MINOR,
        NULL,
        0,
        reply_data,
        1))
    {
        return 0;
    }
    
    return time;
}
