# otp - Implementation of OTP algorithms

## Informations

[![tests](https://github.com/xrjr/otp/actions/workflows/tests.yml/badge.svg)](https://github.com/xrjr/otp/actions/workflows/tests.yml)

### General

This library implements various One Time Password (OTP) algorithms. The main goal of this library is to provide a low level API to the implementations of HOTP and TOTP algorithms. It also provides methods to decode and encode Google Authenticator Key URIs.

> As this package hasn't reached v1 yet, its API shouldn't be considered stable and can change at any moment. However, it is unlikely to happen.

### Supported standards

- HOTP ([rfc 4226](https://www.ietf.org/rfc/rfc4226.txt))
- TOTP ([rfc 6238](https://www.ietf.org/rfc/rfc6238.txt))
- Google Authenticator Key Uri Format ([wiki](https://github.com/google/google-authenticator/wiki/Key-Uri-Format))

## Example usage

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

Using Google Authenticator style Key URIs :

```go
key, err := otp.ParseURI(myuri)

code := otp.TOTP(key.Secret, time.Now(), TOTPOptions{
  HOTPOptions: HOTPOptions{
    Digits: key.Digits,
    Algorithm: key.Algorithm.New,
  },
  Period: key.Period,
})

fmt.Printf("Code : %06d\n", code)
```

Note : standard URI Keys defaults are the same as standard HOTP/TOTP defaults (6 digits, 30 seconds of time period, SHA1 default algorithm).

## Scope

At the moment, the goal of this library isn't to provide all the tools needed to setup a MFA system, but rather the implementations of the algorithms. Thus, some features aren't included, like :
- Key generation
  - You can simply use the `crypto/rand` package.
  - You can choose almost any size for the key, but there are optimal sizes depending on the hash function :
    - [SHA1](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha1.-ctor?view=net-7.0) => 64 bits
    - [SHA256](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha256.-ctor?view=net-7.0) => 64 bits
    - [SHA512](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.hmacsha512.-ctor?view=net-7.0) => 128 bits
- QR code generation
  - You can use your favorite QR code encoder/decoder library
- OTP codes string formatting
  - `fmt.Sprintf` should be fine
- OTP codes validation helpers
  - `TOTPOptions.Step` is useful to compute the code $n$ steps backward or foward