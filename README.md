# TOTP-RFC-6238
Modified the example implementation of TOTP from RFC 6238

Computes the time-based one time password for the current time, using hashing algorithms SHA1, SHA256, and SHA512.

Allows for an output of up to 10 digits, as opposed to the original 8, and takes in a string command line argument
to be encoded in ASCII and used as a shared secret.
