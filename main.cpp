#include "secure_time.h"
#include <stdio.h>

int main(int argc, char *argv[])
{
    int32_t status;
    printf("\n\n\nHello, Secure Time!\n\n");

    status = secure_time_set(12345678);
    printf("secure_time_set() returned %d\n\n", status);

    uint64_t time = secure_time_get();
    printf("secure_time_get() returned %llu\n", time);

    return 0;
}
