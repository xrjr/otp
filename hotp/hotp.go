// hotp implements HOTP as decribed in rfc 4226 (https://www.ietf.org/rfc/rfc4226.txt).
package hotp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"hash"
)

// Client contains base informations to compute OTP code.
type Client struct {
	Key      []byte
	Digits   uint
	HashFunc func() hash.Hash
}

// New returns a HOTP client with a given key.
// Default options are used : Digits = 6, Hash = sha1. You can access and change those options.
func New(key []byte) Client {
	return Client{
		Key:      key,
		Digits:   6,
		HashFunc: sha1.New,
	}
}

// Compute computes the OTP code of a given count.
func (c Client) Compute(count int) uint {
	return dynamicTruncation(hmacShaN(c.HashFunc, c.Key, count)) % pow10(c.Digits)
}

// hmacShaN generates a hmac-sha-n. The hash function is passed as a parameter.
func hmacShaN(hashFunc func() hash.Hash, key []byte, count int) []byte {
	hasher := hmac.New(hashFunc, key)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(count))
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
