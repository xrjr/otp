package otp

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"testing"
)

type KeyTestValue struct {
	Uri           string
	ExpectedError error
	ExpectedKey   Key
}

var keyTestValues = []KeyTestValue{
	// TOTP
	{
		// correctness, defaults
		Uri:           "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeTotp,
			Label:     "Example:alice@google.com",
			Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xde, 0xad, 0xbe, 0xef},
			Issuer:    "Example",
			Algorithm: sha1.New,
			Digits:    6,
			Counter:   0,
			Period:    30,
		},
	},
	{
		// correctness, custom values, counter ignored, algorithm
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30&counter=123456",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeTotp,
			Label:     "ACME Co:john.doe@email.com",
			Secret:    []byte{0x3d, 0xc6, 0xca, 0xa4, 0x82, 0x4a, 0x6d, 0x28, 0x87, 0x67, 0xb2, 0x33, 0x1e, 0x20, 0xb4, 0x31, 0x66, 0xcb, 0x85, 0xd9},
			Issuer:    "ACME Co",
			Algorithm: sha1.New,
			Digits:    6,
			Counter:   0,
			Period:    30,
		},
	},
	{
		// correctness against algorithm
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeTotp,
			Label:     "ACME Co:john.doe@email.com",
			Secret:    []byte{0x3d, 0xc6, 0xca, 0xa4, 0x82, 0x4a, 0x6d, 0x28, 0x87, 0x67, 0xb2, 0x33, 0x1e, 0x20, 0xb4, 0x31, 0x66, 0xcb, 0x85, 0xd9},
			Issuer:    "ACME Co",
			Algorithm: sha256.New,
			Digits:    8,
			Counter:   0,
			Period:    60,
		},
	},
	{
		// correctness against algorithm again
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA512&digits=8&period=60",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeTotp,
			Label:     "ACME Co:john.doe@email.com",
			Secret:    []byte{0x3d, 0xc6, 0xca, 0xa4, 0x82, 0x4a, 0x6d, 0x28, 0x87, 0x67, 0xb2, 0x33, 0x1e, 0x20, 0xb4, 0x31, 0x66, 0xcb, 0x85, 0xd9},
			Issuer:    "ACME Co",
			Algorithm: sha512.New,
			Digits:    8,
			Counter:   0,
			Period:    60,
		},
	},
	{
		// invalid scheme
		Uri:           "example://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
		ExpectedError: ErrInvalidScheme,
		ExpectedKey:   Key{},
	},
	{
		// invalid type
		Uri:           "otpauth://example/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
		ExpectedError: ErrInvalidType,
		ExpectedKey:   Key{},
	},
	{
		// missing secret parameter
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
		ExpectedError: ErrNoSecret,
		ExpectedKey:   Key{},
	},
	{
		// invalid algorithm
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20&algorithm=exampleCo&digits=8&period=60",
		ExpectedError: ErrInvalidAlgorithm,
		ExpectedKey:   Key{},
	},
	{
		// invalid uri (url parsing)
		Uri:           "otp%20auth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&period=60",
		ExpectedError: errors.New(""), // used to check if there is an error, regardless of which one
		ExpectedKey:   Key{},
	},
	{
		// invalid secret (base32 decoding)
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=1XDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&period=60",
		ExpectedError: errors.New(""), // used to check if there is an error, regardless of which one
		ExpectedKey:   Key{},
	},
	{
		// invalid digits parameter (not parsable, negative)
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=example&period=60",
		ExpectedError: strconv.ErrSyntax,
		ExpectedKey:   Key{},
	},
	{
		// invalid period parameter (not parsable, negative)
		Uri:           "otpauth://totp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&period=example",
		ExpectedError: strconv.ErrSyntax,
		ExpectedKey:   Key{},
	},
	// HOTP
	{
		// correctness, defaults
		Uri:           "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=123456",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeHotp,
			Label:     "Example:alice@google.com",
			Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xde, 0xad, 0xbe, 0xef},
			Issuer:    "",
			Algorithm: sha1.New,
			Digits:    6,
			Counter:   123456,
			Period:    0,
		},
	},
	{
		// correctness, custom, period ignored, other algorithm
		Uri:           "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=123456&issuer=Example&algorithm=SHA256&digits=8&period=30",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeHotp,
			Label:     "Example:alice@google.com",
			Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xde, 0xad, 0xbe, 0xef},
			Issuer:    "Example",
			Algorithm: sha256.New,
			Digits:    8,
			Counter:   123456,
			Period:    0,
		},
	},
	{
		// correctness against algorithm
		Uri:           "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=123456&issuer=Example&algorithm=SHA512&digits=8",
		ExpectedError: nil,
		ExpectedKey: Key{
			Type:      TypeHotp,
			Label:     "Example:alice@google.com",
			Secret:    []byte{'H', 'e', 'l', 'l', 'o', '!', 0xde, 0xad, 0xbe, 0xef},
			Issuer:    "Example",
			Algorithm: sha512.New,
			Digits:    8,
			Counter:   123456,
			Period:    0,
		},
	},
	{
		// invalid scheme
		Uri:           "example://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=123456&issuer=Example&algorithm=SHA512&digits=8",
		ExpectedError: ErrInvalidScheme,
		ExpectedKey:   Key{},
	},
	{
		// invalid type
		Uri:           "otpauth://example/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=123456&issuer=Example&algorithm=SHA512&digits=8",
		ExpectedError: ErrInvalidType,
		ExpectedKey:   Key{},
	},
	{
		// invalid secret
		Uri:           "otpauth://hotp/Example:alice@google.com?issuer=Example&algorithm=SHA512&digits=8",
		ExpectedError: ErrNoSecret,
		ExpectedKey:   Key{},
	},
	{
		// missing counter parameter
		Uri:           "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA512&digits=8",
		ExpectedError: ErrNoCounter,
		ExpectedKey:   Key{},
	},
	{
		// invalid algorithm
		Uri:           "otpauth://hotp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&counter=123456&issuer=Example&algorithm=example&digits=8",
		ExpectedError: ErrInvalidAlgorithm,
		ExpectedKey:   Key{},
	},
	{
		// invalid uri (url parsing)
		Uri:           "otp%20auth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&counter=123456",
		ExpectedError: errors.New(""), // used to check if there is an error, regardless of which one
		ExpectedKey:   Key{},
	},
	{
		// invalid secret (base32 parsing)
		Uri:           "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=1XDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&counter=123456",
		ExpectedError: errors.New(""), // used to check if there is an error, regardless of which one
		ExpectedKey:   Key{},
	},
	{
		// invalid digits parameter (not parsable, negative)
		Uri:           "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=example&counter=123456",
		ExpectedError: strconv.ErrSyntax,
		ExpectedKey:   Key{},
	},
	{
		// invalid counter parameter (not parsable, negative)
		Uri:           "otpauth://hotp/ACME%20Co:john.doe@email.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=ACME%20Co&digits=8&counter=example",
		ExpectedError: strconv.ErrSyntax,
		ExpectedKey:   Key{},
	},
}

func TestParseURI(t *testing.T) {
	for i, testValue := range keyTestValues {
		key, err := ParseURI(testValue.Uri)

		if !errors.Is(err, testValue.ExpectedError) && !strings.Contains(err.Error(), testValue.ExpectedError.Error()) {
			fmt.Println(err)
			t.Errorf("Error in ParseURI (error check, i = %d)", i)
			return
		}
		if err != nil {
			continue
		}

		if ok, step := keysEqual(key, testValue.ExpectedKey); !ok {
			t.Errorf("Error in ParseURI (equality check, i = %d, step = %s)", i, step)
		}
	}
}

func keysEqual(key1, key2 Key) (bool, string) {
	if key1.Type != key2.Type {
		return false, "type"
	}

	if key1.Label != key2.Label {
		return false, "label"
	}

	if !bytes.Equal(key1.Secret, key2.Secret) {
		return false, "secret"
	}

	if key1.Issuer != key2.Issuer {
		return false, "issuer"
	}

	// Algorithm is supposed non-nil because keys equality check only appears if err = nil
	if !hashFuncEqual(key1.Algorithm, key2.Algorithm) {
		return false, "algorithm"
	}

	if key1.Digits != key2.Digits {
		return false, "digits"
	}

	if key1.Counter != key2.Counter {
		return false, "counter"
	}

	if key1.Period != key2.Period {
		return false, "period"
	}

	return true, ""
}

func hashFuncEqual(h1, h2 func() hash.Hash) bool {
	exampleData := []byte{0x0, 0x1, 0x2, 0x3}
	hash1 := h1().Sum(exampleData)
	hash2 := h2().Sum(exampleData)
	return bytes.Equal(hash1, hash2)
}

func TestKeyToHOTPOptions(t *testing.T) {
	for i, testValue := range keyTestValues {
		if testValue.ExpectedError == nil {
			opts := testValue.ExpectedKey.HOTPOptions()

			if !hashFuncEqual(opts.Algorithm, testValue.ExpectedKey.Algorithm) ||
				opts.Digits != testValue.ExpectedKey.Digits {
				t.Errorf("Error in KeyToHOTPOptions (i = %d)", i)
			}
		}
	}
}

func TestKeyToTOTPOptions(t *testing.T) {
	for i, testValue := range keyTestValues {
		if testValue.ExpectedError == nil {
			opts := testValue.ExpectedKey.TOTPOptions()

			if !hashFuncEqual(opts.Algorithm, testValue.ExpectedKey.Algorithm) ||
				opts.Digits != testValue.ExpectedKey.Digits ||
				opts.Period != testValue.ExpectedKey.Period {
				t.Errorf("Error in KeyToHOTPOptions (i = %d)", i)
			}
		}
	}
}
