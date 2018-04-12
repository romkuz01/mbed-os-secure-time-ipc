# Secure Time IPC Example

This is a sample implementation of Secure Time partition along with a short usage example.

## File List

secure_time_partition_psa.json - Secure Time partition description containing all the Secure Functions provided to the user
secure_time_partition.c - Secure Time partition thread that handles user's requests
secure_time_client.c - IPC implementations of Secure Functions declared in mbed-os/secure_time/secure_time.h and mbed-os/secure_time/secure_time_spe.h
main.cpp - a short usage example showing a sample Secure Time API call via the IPC implementation
.mbedignore - a list of files that should be ignored during compilation to prevent Secure Time API function name conflicts

## Compilation and Execution

```
git clone git@github.com:romkuz01/mbed-os-secure-time-ipc
cd mbed-os-secure-time-ipc
git clone git@github.com:kfnta/mbed-os.git -b romkuz01_secure_time
mbed compile -m K64F -t GCC_ARM
```
At the end of the compilation process an application binary will be created - BUILD/K64F/GCC_ARM/secure_time_app.bin.
This binary can be copied to your target board connected via USB cable.
The output produced by the application can be seen in any program capable of monitoring COM port traffic (PuTTY for example).

