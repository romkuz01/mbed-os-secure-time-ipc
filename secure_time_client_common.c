#include "secure_time_client_common.h"
#include <stdint.h>

int32_t psa_invoke_sf(
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
