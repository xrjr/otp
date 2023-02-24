package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"errors"
	"hash"
	"net/url"
	"strconv"
)

const (
	uriScheme = "otpauth"
	typeTotp  = "totp"
	typeHotp  = "hotp"

	queryKeySecret    = "secret"
	queryKeyIssuer    = "issuer"
	queryKeyAlgorithm = "algorithm"
	queryKeyDigits    = "digits"
	queryKeyCounter   = "counter"
	queryKeyPeriod    = "period"
)

var (
	algorithms = map[string]func() hash.Hash{
		"SHA1":   sha1.New,
		"SHA256": sha256.New,
		"SHA512": sha512.New,
	}
)

var (
	ErrInvalidScheme    = errors.New("invalid scheme")
	ErrInvalidType      = errors.New("invalid type")
	ErrNoScret          = errors.New("no secret provided")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
	ErrNoCounter        = errors.New("no counter provided")
)

type Key struct {
	Type      string
	Label     string
	Secret    []byte
	Issuer    string
	Algorithm func() hash.Hash
	Digits    int
	Counter   int
	Period    int
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
	if parsed.Host != typeTotp && parsed.Host != typeHotp {
		return res, ErrInvalidType
	}
	res.Type = parsed.Host

	// label
	res.Label = parsed.Path

	// secret (+validation)
	if !parsed.Query().Has(queryKeySecret) {
		return res, ErrNoScret
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
		algorithm, ok := algorithms[algorithmRaw]

		if !ok {
			return res, ErrInvalidAlgorithm
		}

		res.Algorithm = algorithm
	} else {
		res.Algorithm = sha1.New
	}

	// digits
	if parsed.Query().Has(queryKeyDigits) {
		digits, err := strconv.ParseInt(parsed.Query().Get(queryKeyDigits), 10, 0)
		if err != nil {
			return res, err
		}
		res.Digits = int(digits)
	} else {
		res.Digits = 6
	}

	// counter (only hotp)
	if res.Type == typeHotp {
		if !parsed.Query().Has(queryKeyCounter) {
			return res, ErrNoCounter
		} else {
			counter, err := strconv.ParseInt(parsed.Query().Get(queryKeyCounter), 10, 0)
			if err != nil {
				return res, err
			}
			res.Counter = int(counter)
		}
	}

	// period (only totp)
	if res.Type == typeTotp {
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
