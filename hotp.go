package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash"
)

type HOTPOptions struct {
	Digits    uint
	Algorithm func() hash.Hash
}

// HOTP computes the OTP code of a given counter.
func HOTP(key []byte, counter int, opts HOTPOptions) uint {
	// defaults
	if opts.Algorithm == nil {
		opts.Algorithm = sha1.New
	}

	if opts.Digits == 0 {
		opts.Digits = 6
	}

	// compute
	return dynamicTruncation(hmacShaN(opts.Algorithm, key, counter)) % pow10(opts.Digits)
}

// hmacShaN generates a hmac-sha-n. The hash function is passed as a parameter.
func hmacShaN(hashFunc func() hash.Hash, key []byte, counter int) []byte {
	hasher := hmac.New(hashFunc, key)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(counter))
	hasher.Write(buf)
	return hasher.Sum(nil)
}

// pow10 computes the n-th power of 10.
// Here we doesn't use math.Pow10 to avoid type casting and high complexity of this function.
// This might change in the future.
func pow10(n uint) uint {
	res := uint(1)
	for i := uint(0); i < n; i++ {
		res *= 10
	}
	return res
}

// dynamicTruncation is the DT function of the section 5.4 of the rfc.
func dynamicTruncation(hs []byte) uint {
	offset := hs[len(hs)-1] & 0xf
	return uint(binary.BigEndian.Uint32(hs[offset:offset+4])) & 0x7fffffff
}
