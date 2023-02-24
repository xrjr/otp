# otp - Implmentation of OTP algorithms

## Informations

[![tests](https://github.com/xrjr/otp/actions/workflows/tests.yml/badge.svg)](https://github.com/xrjr/otp/actions/workflows/tests.yml)

### General

This library implements various One Time Password (OTP) algorithms. The main goal if this library is to provide low level implementations of those.

It can be used as a base block for building a 2FA system.

### Supported standards

- HOTP ([rfc 4226](https://www.ietf.org/rfc/rfc4226.txt))
- TOTP ([rfc 6238](https://www.rfc-editor.org/rfc/rfc6238))
- Google Authenticator Key Uri Format ([wiki](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))

### Limitations

This library doesn't have the goal to porvide all the tools needed to setup a 2FA, but rather the low level implementations of the algorithms. Thus, some features are missing like :
- Secret key generation
- QR code generation
- OTP codes string formatting
- OTP codes validation helpers (multiple time steps at once for example)