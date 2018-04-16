#include "psa_defs.h"
#include "spm_client.h"
#include "psa_client_common.h"
#include "secure_time_client_common.h"
#include "secure_time_client.h"
#include "secure_time_client_spe.h"

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
