# otp - HOTP and TOTP in Go

## Informations

[![tests](https://github.com/xrjr/otp/actions/workflows/tests.yml/badge.svg)](https://github.com/xrjr/otp/actions/workflows/tests.yml)

### General

This library implements HMAC-based One-Time Password (HOTP) and Time-based One-Time Password (TOTP) algorithms. 

> As this package hasn't reached v1 yet, its API shouldn't be considered stable and can change at any moment. However, it is unlikely to happen.

### Supported standards

- HOTP ([rfc 4226](https://www.ietf.org/rfc/rfc4226.txt))
- TOTP ([rfc 6238](https://www.ietf.org/rfc/rfc6238.txt))

## TOTP example usage

Using defaults :

```go
code := otp.TOTP(secret, time.Now(), TOTPOptions{})
```

Using options :

```go
code := otp.TOTP(secret, time.Now(), TOTPOptions{
  HOTPOptions: HOTPOptions{
    Digits: 8,
  },
  Period: 60,
  Step: -1,
})
```

Default options are :

- 6 digits
- 30 seconds time period
- SHA1 hash function

