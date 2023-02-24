// key implements Google Authenticator Key Uri Format as described by the google-authenticator wiki (https://github.com/google/google-authenticator/wiki/Key-Uri-Format).
package otp

import (
	"crypto"
	_ "crypto/sha1"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base32"
	"errors"
	"fmt"
	"net/url"
	"strconv"
)

const (
	uriScheme = "otpauth"
	TypeTOTP  = "totp"
	TypeHOTP  = "hotp"

	queryKeySecret    = "secret"
	queryKeyIssuer    = "issuer"
	queryKeyAlgorithm = "algorithm"
	queryKeyDigits    = "digits"
	queryKeyCounter   = "counter"
	queryKeyPeriod    = "period"
)

var (
	algorithmsStringToHash = map[string]crypto.Hash{
		"SHA1":   crypto.SHA1,
		"SHA256": crypto.SHA256,
		"SHA512": crypto.SHA512,
	}

	algorithmsHashToString = map[crypto.Hash]string{
		0:             "SHA1", // defaults to sha1
		crypto.SHA1:   "SHA1",
		crypto.SHA256: "SHA256",
		crypto.SHA512: "SHA512",
	}
)

var (
	ErrInvalidScheme    = errors.New("invalid scheme")
	ErrInvalidType      = errors.New("invalid type")
	ErrMissingSecret    = errors.New("no secret provided")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrMissingCounter   = errors.New("no counter provided")
)

type Key struct {
	Type      string
	Label     string
	Secret    []byte
	Issuer    string
	Algorithm crypto.Hash
	Digits    uint
	Counter   int
	Period    int
}

func (key *Key) HOTPOptions() HOTPOptions {
	return HOTPOptions{
		Digits:    key.Digits,
		Algorithm: key.Algorithm.New,
	}
}

func (key *Key) TOTPOptions() TOTPOptions {
	return TOTPOptions{
		HOTPOptions: key.HOTPOptions(),
		Period:      key.Period,
	}
}

func ParseURI(uri string) (Key, error) {
	res := Key{}

	parsed, err := url.Parse(uri)
	if err != nil {
		return res, err
	}

	// scheme validation
	if parsed.Scheme != uriScheme {
		return res, ErrInvalidScheme
	}

	// type (+validation)
	if parsed.Host != TypeTOTP && parsed.Host != TypeHOTP {
		return res, ErrInvalidType
	}
	res.Type = parsed.Host

	// label
	res.Label = parsed.Path[1:]

	// secret (+validation)
	if !parsed.Query().Has(queryKeySecret) || parsed.Query().Get(queryKeySecret) == "" {
		return res, ErrMissingSecret
	}

	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(parsed.Query().Get(queryKeySecret))
	if err != nil {
		return res, err
	}
	res.Secret = secret

	// issuer
	res.Issuer = parsed.Query().Get(queryKeyIssuer)

	// algorithm
	if parsed.Query().Has(queryKeyAlgorithm) {
		algorithmRaw := parsed.Query().Get(queryKeyAlgorithm)
		algorithm, ok := algorithmsStringToHash[algorithmRaw]

		if !ok {
			return res, ErrInvalidAlgorithm
		}

		res.Algorithm = algorithm
	} else {
		res.Algorithm = crypto.SHA1
	}

	// digits
	if parsed.Query().Has(queryKeyDigits) {
		digits, err := strconv.ParseUint(parsed.Query().Get(queryKeyDigits), 10, 0)
		if err != nil {
			return res, err
		}
		res.Digits = uint(digits)
	} else {
		res.Digits = 6
	}

	// counter (only hotp)
	if res.Type == TypeHOTP {
		if !parsed.Query().Has(queryKeyCounter) {
			return res, ErrMissingCounter
		} else {
			counter, err := strconv.ParseInt(parsed.Query().Get(queryKeyCounter), 10, 0)
			if err != nil {
				return res, err
			}
			res.Counter = int(counter)
		}
	}

	// period (only totp)
	if res.Type == TypeTOTP {
		if parsed.Query().Has(queryKeyPeriod) {
			period, err := strconv.ParseInt(parsed.Query().Get(queryKeyPeriod), 10, 0)
			if err != nil {
				return res, err
			}
			res.Period = int(period)
		} else {
			res.Period = 30
		}
	}

	return res, nil
}

func (key Key) URI() (string, error) {
	if key.Type != TypeHOTP && key.Type != TypeTOTP {
		return "", ErrInvalidType
	}

	params := make(url.Values)

	if len(key.Secret) == 0 {
		return "", ErrMissingSecret
	}

	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(key.Secret)
	params.Set(queryKeySecret, secret)

	if key.Issuer != "" {
		params.Set(queryKeyIssuer, key.Issuer)
	}

	if key.Digits != 0 {
		params.Set(queryKeyIssuer, key.Issuer)
	}

	algorithm, ok := algorithmsHashToString[key.Algorithm] // defaults to sha1
	if !ok {
		return "", ErrInvalidAlgorithm
	}
	params.Set(queryKeyAlgorithm, algorithm)

	if key.Type == TypeHOTP {
		params.Set(queryKeyCounter, strconv.FormatInt(int64(key.Counter), 10)) // no need to check counter because of zero value
	} else {
		if key.Period != 0 {
			params.Set(queryKeyPeriod, strconv.FormatInt(int64(key.Period), 10))
		}
	}

	return fmt.Sprintf("otpauth://%s/%s?%s", key.Type, key.Label, params.Encode()), nil
}
