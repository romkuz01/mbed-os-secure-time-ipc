#include "psa_defs.h"
#include "spm_client.h"
#include "psa_client_common.h"
#include "secure_time.h"
#include "secure_time_spe.h"

#define GET_NONCE_MINOR           1
#define TIME_GET_MINOR            1
#define TIME_SET_MINOR            1
#define TIME_SET_TRUSTED_MINOR    1
#define SET_SCHEMA_MINOR          1
#define GET_SCHEMA_MINOR          1
#define SET_PUBLIC_KEY_MINOR      1
#define GET_PUBLIC_KEY_SIZE_MINOR 1
#define GET_PUBLIC_KEY_MINOR      1

static int32_t psa_invoke_sf(
    uint32_t sfid,
    uint32_t minor_version,
    const psa_invec_t *in_vec,
    size_t in_len,
    const psa_outvec_t *out_vec,
    size_t out_len
    )
{
    psa_handle_t connection_handle = psa_connect(sfid, minor_version);
    if (connection_handle == PSA_NULL_HANDLE) {
        return 0;
    }

    if (psa_call(connection_handle, in_vec, in_len, out_vec, out_len) != PSA_SUCCESS) {
        return 0;
    }
    
    if (psa_close(connection_handle) != PSA_SUCCESS) {
        return 0;
    }

    return 1;
}

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

int32_t secure_time_set_stored_schema(const secure_time_schema_t *schema)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {schema, sizeof(secure_time_schema_t)}
    };
    psa_outvec_t reply_data[1] = {
        {&reply_status, sizeof(int32_t)}
    };
    
    if (!psa_invoke_sf(
        SET_SCHEMA,
        SET_SCHEMA_MINOR,
        request_data,
        1,
        reply_data,
        1))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

int32_t secure_time_get_stored_schema(secure_time_schema_t *schema)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_outvec_t reply_data[2] = {
        {&reply_status, sizeof(int32_t)},
        {schema, sizeof(secure_time_schema_t)}
    };

    if (!psa_invoke_sf(
        GET_SCHEMA,
        GET_SCHEMA_MINOR,
        NULL,
        0,
        reply_data,
        2))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

int32_t secure_time_set_stored_public_key(const void *pubkey, size_t key_size)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {pubkey, key_size}
    };
    psa_outvec_t reply_data[1] = {
        {&reply_status, sizeof(int32_t)}
    };
    
    if (!psa_invoke_sf(
        SET_PUBLIC_KEY,
        SET_PUBLIC_KEY_MINOR,
        request_data,
        1,
        reply_data,
        1))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

int32_t secure_time_get_stored_public_key_size(size_t *actual_size)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_outvec_t reply_data[2] = {
        {&reply_status, sizeof(int32_t)},
        {actual_size, sizeof(size_t)}
    };

    if (!psa_invoke_sf(
        GET_PUBLIC_KEY_SIZE,
        GET_PUBLIC_KEY_SIZE_MINOR,
        NULL,
        0,
        reply_data,
        2))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}

int32_t secure_time_get_stored_public_key(uint8_t *pubkey, size_t size, size_t *actual_size)
{
    int32_t reply_status = SECURE_TIME_SUCCESS;
    psa_invec_t request_data[1] = {
        {&size, sizeof(size_t)}
    };
    psa_outvec_t reply_data[3] = {
        {&reply_status, sizeof(int32_t)},
        {pubkey, size},
        {actual_size, sizeof(size_t)}
    };

    if (!psa_invoke_sf(
        GET_PUBLIC_KEY,
        GET_PUBLIC_KEY_MINOR,
        request_data,
        1,
        reply_data,
        3))
    {
        return SECURE_TIME_PSA_IPC_ERROR;
    }
    
    return reply_status;
}
