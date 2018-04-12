# Secure Time IPC Example

This is a sample implementation of Secure Time partition along with a short usage example.

## File List

secure_time_partition_psa.json - Secure Time partition description containing all the Secure Functions provided to the user
secure_time_partition.c - Secure Time partition thread that handles user's requests
secure_time_client.c - IPC implementations of Secure Functions declared in mbed-os/secure_time/secure_time.h and mbed-os/secure_time/secure_time_spe.h
main.cpp - a short usage example showing a sample Secure Time API call via the IPC implementation
.mbedignore - a list of files that should be ignored during compilation to prevent Secure Time API function name conflicts

## Compilation

```
git clone git@github.com:romkuz01/mbed-os-secure-time-ipc
cd mbed-os-secure-time-ipc
git clone git@github.com:kfnta/mbed-os.git -b romkuz01_secure_time
```
