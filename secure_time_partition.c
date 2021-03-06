#include "spm_server.h"
#include "spm_panic.h"
#include "psa_secure_time_partition.h"
#include "secure_time_impl.h"
#include <string.h>

static int32_t call_secure_time_set_trusted_init(psa_msg_t *msg)
{
    int32_t set_trusted_init_status = SECURE_TIME_SUCCESS;
    uint64_t nonce = 0;

    if (msg->out_size[0] != sizeof(int32_t) || msg->out_size[1] != sizeof(uint64_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    set_trusted_init_status = secure_time_set_trusted_init_impl(&nonce);
    psa_write(msg->handle, 0, &set_trusted_init_status, sizeof(int32_t));

    if (set_trusted_init_status == SECURE_TIME_SUCCESS) {
        psa_write(msg->handle, 1, &nonce, sizeof(uint64_t));
    }

    return PSA_SUCCESS;
}

static int32_t call_secure_time_set_trusted_commit(psa_msg_t *msg)
{
    int32_t time_set_commit_status = SECURE_TIME_SUCCESS;
    void *blob = NULL;
    size_t blob_size = msg->in_size[0];

    if (!blob_size ||msg->out_size[0] != sizeof(int32_t)) {
        return PSA_INVALID_PARAMETERS;
    }

    if (!(blob = malloc(blob_size))) {
        return PSA_MEM_ALLOC_FAILED;
    }
    
    if (psa_read(msg->handle, 0, blob, blob_size) != blob_size) {
        SPM_PANIC("Failed to read the blob!\n");
    }

    time_set_commit_status = secure_time_set_trusted_commit_impl(blob, blob_size);
    psa_write(msg->handle, 0, &time_set_commit_status, sizeof(int32_t));
    
    free(blob);
    
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
    uint32_t signals_lowest_one_cleaned = 0;
    uint32_t signal = 0;
    psa_msg_t msg = {0};
    int32_t result;
    
    while (1) {
        signals = psa_wait_any(PSA_WAIT_BLOCK);

        if (signals == 0 || (signals | SECURE_TIME_WAIT_ANY_SFID_MSK) != SECURE_TIME_WAIT_ANY_SFID_MSK) {
            SPM_PANIC("Unexpected signal(s) %d!\n", (int)signals);
        }

        // Extract the lowest asserted signal.
        signals_lowest_one_cleaned = signals & (signals - 1);
        signal = signals ^ signals_lowest_one_cleaned;

        psa_get(signal, &msg);

        switch (msg.type)
        {
            case PSA_IPC_MSG_TYPE_CONNECT:
                psa_end(msg.handle, PSA_SUCCESS);
                break;
            case PSA_IPC_MSG_TYPE_CALL:
                switch (signal) {
                    case TIME_SET_TRUSTED_INIT_MSK:
                        result = call_secure_time_set_trusted_init(&msg);
                        break;
                    case TIME_SET_TRUSTED_COMMIT_MSK:
                        result = call_secure_time_set_trusted_commit(&msg);
                        break;
                    case TIME_SET_MSK:
                        result = call_secure_time_set(&msg);
                        break;
                    case TIME_GET_MSK:
                        result = call_secure_time_get(&msg);
                        break;
                    case SET_PUBLIC_KEY_MSK:
                        result = call_secure_time_set_stored_public_key(&msg);
                        break;
                    case GET_PUBLIC_KEY_SIZE_MSK:
                        result = call_secure_time_get_stored_public_key_size(&msg);
                        break;
                    case GET_PUBLIC_KEY_MSK:
                        result = call_secure_time_get_stored_public_key(&msg);
                        break;
                    default:
                        SPM_PANIC("Unexpected signal %d (must be a programming error)!\n", signal);
                }
                psa_end(msg.handle, result);
                break;
            case PSA_IPC_MSG_TYPE_DISCONNECT:
                psa_end(msg.handle, PSA_SUCCESS);
                break;
            default:
                SPM_PANIC("Unexpected message type %d!\n", (int)msg.type);
        }
    }
}