#include "secure_time_client_common.h"
#include "spm_client.h"
#include "mbed_wait_api.h"
#include <stdint.h>
#include <stdlib.h>

#define CONNECT_RETRY_COUNT 10
#define CONNECT_WAIT_MS_MAX 5

int32_t psa_invoke_sf(
    uint32_t sfid,
    uint32_t minor_version,
    const psa_invec_t *in_vec,
    size_t in_len,
    const psa_outvec_t *out_vec,
    size_t out_len
    )
{
    psa_handle_t connection_handle = PSA_NULL_HANDLE;
    uint32_t i = 0;

    for (i = 0;
        i < CONNECT_RETRY_COUNT &&
        (connection_handle = psa_connect(sfid, minor_version)) == PSA_CONNECTION_REFUSED_BUSY;
        i++) {
        wait_ms(rand() % CONNECT_WAIT_MS_MAX);
    }

    if (connection_handle < 0) {
        return 0;
    }

    if (psa_call(connection_handle, in_vec, in_len, out_vec, out_len) != PSA_SUCCESS) {
        psa_close(connection_handle);
        return 0;
    }
    
    if (psa_close(connection_handle) != PSA_SUCCESS) {
        return 0;
    }

    return 1;
}
