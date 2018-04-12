#include "spm_server.h"
#include "spm_panic.h"
#include "psa_secure_time_partition.h"
#include "secure_time_impl.h"
#include "secure_time_spe_impl.h"
#include <string.h>

typedef int32_t (*psa_call)(psa_msg_t *msg);

static int32_t call_secure_time_get_nonce(psa_msg_t *msg)
{
    uint32_t nonce_size = 0;
    void *nonce = NULL;
    int32_t get_nonce_status = SECURE_TIME_SUCCESS;

    if (msg->in_size[0] != sizeof(uint32_t) || msg->out_size[0] != sizeof(int32_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (psa_read(msg->handle, 0, &nonce_size, sizeof(uint32_t)) != sizeof(uint32_t)) {
        SPM_PANIC("Failed to read the requested nonce size!\n");
    }

    if (msg->out_size[1] != nonce_size) {
        return PSA_INVALID_PARAMETERS;
    }
    
    if (!(nonce = malloc(nonce_size))) {
        return PSA_MEM_ALLOC_FAILED;
    }

    get_nonce_status = secure_time_get_nonce_impl(nonce_size, nonce);
    psa_write(msg->handle, 0, &get_nonce_status, sizeof(int32_t));

    if (get_nonce_status == SECURE_TIME_SUCCESS) {
        psa_write(msg->handle, 1, nonce, nonce_size);
    }

    free(nonce);
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_set_trusted(psa_msg_t *msg)
{
    int32_t time_set_status = SECURE_TIME_SUCCESS;
    void *blob = NULL;
    void *sign = NULL;
    size_t blob_size = msg->in_size[0];
    size_t sign_size = msg->in_size[1];

    if (!blob_size || !sign_size || msg->out_size[0] != sizeof(int32_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (!(blob = malloc(blob_size)) || !(sign = malloc(sign_size))) {
        free(blob);
        return PSA_MEM_ALLOC_FAILED;
    }
    
    if (psa_read(msg->handle, 0, blob, blob_size) != blob_size) {
        SPM_PANIC("Failed to read the blob!\n");
    }

    if (psa_read(msg->handle, 1, sign, sign_size) != sign_size) {
        SPM_PANIC("Failed to read the signature!\n");
    }
    
    time_set_status = secure_time_set_trusted_impl(blob, blob_size, sign, sign_size);
    psa_write(msg->handle, 0, &time_set_status, sizeof(int32_t));
    
    free(blob);
    free(sign);
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_set(psa_msg_t *msg)
{
    uint64_t new_time = 0;
    int32_t time_set_status = SECURE_TIME_SUCCESS;

    if (msg->in_size[0] != sizeof(uint64_t) || msg->out_size[0] != sizeof(int32_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (psa_read(msg->handle, 0, &new_time, sizeof(uint64_t)) != sizeof(uint64_t)) {
        SPM_PANIC("Failed to read the requested new time to set!\n");
    }
    time_set_status = secure_time_set_impl(new_time);
    psa_write(msg->handle, 0, &time_set_status, sizeof(int32_t));
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_get(psa_msg_t *msg)
{
    uint64_t time = 0;

    if (msg->out_size[0] != sizeof(uint64_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    time = secure_time_get_impl();

    psa_write(msg->handle, 0, &time, sizeof(uint64_t));
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_set_stored_schema(psa_msg_t *msg)
{
    secure_time_schema_t schema = {0};
    int32_t set_schema_status = SECURE_TIME_SUCCESS;

    if (msg->in_size[0] != sizeof(secure_time_schema_t) || msg->out_size[0] != sizeof(int32_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (psa_read(msg->handle, 0, &schema, sizeof(secure_time_schema_t)) != sizeof(secure_time_schema_t)) {
        SPM_PANIC("Failed to read the requested schema to set!\n");
    }

    set_schema_status = secure_time_set_stored_schema_impl(&schema);
    psa_write(msg->handle, 0, &set_schema_status, sizeof(int32_t));
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_get_stored_schema(psa_msg_t *msg)
{
    secure_time_schema_t schema = {0};
    int32_t get_schema_status = SECURE_TIME_SUCCESS;

    if (msg->out_size[0] != sizeof(int32_t) || msg->out_size[1] != sizeof(secure_time_schema_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    get_schema_status = secure_time_get_stored_schema_impl(&schema);
    psa_write(msg->handle, 0, &get_schema_status, sizeof(int32_t));

    if (get_schema_status == SECURE_TIME_SUCCESS) {
        psa_write(msg->handle, 1, &schema, sizeof(secure_time_schema_t));
    }
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_set_stored_public_key(psa_msg_t *msg)
{
    size_t key_size = msg->in_size[0];
    void *key = NULL;
    int32_t set_key_status = SECURE_TIME_SUCCESS;

    if (!key_size || msg->out_size[0] != sizeof(int32_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (!(key = malloc(key_size))) {
        return PSA_MEM_ALLOC_FAILED;
    }
    
    if (psa_read(msg->handle, 0, key, key_size) != key_size) {
        SPM_PANIC("Failed to read the public key!\n");
    }

    set_key_status = secure_time_set_stored_public_key_impl(key, key_size);
    psa_write(msg->handle, 0, &set_key_status, sizeof(int32_t));
    
    free(key);
    
    return PSA_SUCCESS;
}

static int32_t call_secure_time_get_stored_public_key_size(psa_msg_t *msg)
{
    size_t actual_size = 0;
    int32_t get_key_size_status = SECURE_TIME_SUCCESS;

    if (msg->out_size[0] != sizeof(int32_t) || msg->out_size[1] != sizeof(size_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    get_key_size_status = secure_time_get_stored_public_key_size_impl(&actual_size);
    psa_write(msg->handle, 0, &get_key_size_status, sizeof(int32_t));

    if (get_key_size_status == SECURE_TIME_SUCCESS) {
        psa_write(msg->handle, 1, &actual_size, sizeof(size_t));
    }

    return PSA_SUCCESS;
}

static int32_t call_secure_time_get_stored_public_key(psa_msg_t *msg)
{
    size_t buf_size = 0;
    uint8_t *key = NULL;
    size_t actual_size = 0;
    int32_t get_key_status = SECURE_TIME_SUCCESS;

    if (msg->in_size[0] != sizeof(size_t) || msg->out_size[0] != sizeof(int32_t) || msg->out_size[2] != sizeof(size_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (psa_read(msg->handle, 0, &buf_size, sizeof(size_t)) != sizeof(size_t)) {
        SPM_PANIC("Failed to read the key buffer size!\n");
    }

    if (msg->out_size[1] != buf_size) {
        return PSA_INVALID_PARAMETERS;
    }

    if (!(key = malloc(buf_size))) {
        return PSA_MEM_ALLOC_FAILED;
    }

    get_key_status = secure_time_get_stored_public_key_impl(key, buf_size, &actual_size);
    psa_write(msg->handle, 0, &get_key_status, sizeof(int32_t));
    psa_write(msg->handle, 2, &actual_size, sizeof(size_t));

    if (get_key_status == SECURE_TIME_SUCCESS) {
        psa_write(msg->handle, 1, key, actual_size);
    }

    return PSA_SUCCESS;
}

void secure_time_main(void *ptr)
{
    uint32_t signals = 0;
    psa_signal_t signal = 0;
    psa_call sf_call = NULL;
    psa_msg_t msg = {0};
    
    while (1) {
        signals = psa_wait_any(PSA_WAIT_BLOCK);

        if ((signals & GET_NONCE_MSK)) {
            signal = GET_NONCE_MSK;
            sf_call = call_secure_time_get_nonce;
        }
        else
        if ((signals & TIME_SET_TRUSTED_MSK)) {
            signal = TIME_SET_TRUSTED_MSK;
            sf_call = call_secure_time_set_trusted;
        }
        else
        if ((signals & TIME_SET_MSK)) {
            signal = TIME_SET_MSK;
            sf_call = call_secure_time_set;
        }
        else
        if ((signals & TIME_GET_MSK)) {
            signal = TIME_GET_MSK;
            sf_call = call_secure_time_get;
        }
        else
        if ((signals & SET_SCHEMA_MSK)) {
            signal = SET_SCHEMA_MSK;
            sf_call = call_secure_time_set_stored_schema;
        }
        else
        if ((signals & GET_SCHEMA_MSK)) {
            signal = GET_SCHEMA_MSK;
            sf_call = call_secure_time_get_stored_schema;
        }
        else
        if ((signals & SET_PUBLIC_KEY_MSK)) {
            signal = SET_PUBLIC_KEY_MSK;
            sf_call = call_secure_time_set_stored_public_key;
        }
        else
        if ((signals & GET_PUBLIC_KEY_SIZE_MSK)) {
            signal = GET_PUBLIC_KEY_SIZE_MSK;
            sf_call = call_secure_time_get_stored_public_key_size;
        }
        else
        if ((signals & GET_PUBLIC_KEY_MSK)) {
            signal = GET_PUBLIC_KEY_MSK;
            sf_call = call_secure_time_get_stored_public_key;
        }
        else {
            SPM_PANIC("Unexpected signal(s) %d!\n", (int)signals);
        }

        psa_get(signal, &msg);

        switch (msg.type)
        {
            case PSA_IPC_MSG_TYPE_CONNECT:
                psa_end(msg.handle, PSA_SUCCESS);
                break;
            case PSA_IPC_MSG_TYPE_CALL:
                psa_end(msg.handle, sf_call(&msg));
                break;
            case PSA_IPC_MSG_TYPE_DISCONNECT:
                psa_end(msg.handle, PSA_SUCCESS);
                break;
            default:
                SPM_PANIC("Unexpected message type %d!\n", (int)msg.type);
        }
    }
}