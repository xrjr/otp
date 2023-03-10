package otp

import (
	"bytes"
	"crypto/sha1"
	"testing"
)

type HOTPTestValue struct {
	Counter              int
	Secret               []byte
	IntermediateHmacSha1 []byte
	Truncated            uint
	OTP                  uint
}

var hotpSecret = []byte("12345678901234567890")

var hotpTestValues = []HOTPTestValue{
	{
		Counter:              0,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0xcc, 0x93, 0xcf, 0x18, 0x50, 0x8d, 0x94, 0x93, 0x4c, 0x64, 0xb6, 0x5d, 0x8b, 0xa7, 0x66, 0x7f, 0xb7, 0xcd, 0xe4, 0xb0},
		Truncated:            0x4c93cf18,
		OTP:                  755224,
	},
	{
		Counter:              1,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0x75, 0xa4, 0x8a, 0x19, 0xd4, 0xcb, 0xe1, 0x00, 0x64, 0x4e, 0x8a, 0xc1, 0x39, 0x7e, 0xea, 0x74, 0x7a, 0x2d, 0x33, 0xab},
		Truncated:            0x41397eea,
		OTP:                  287082,
	},
	{
		Counter:              2,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0x0b, 0xac, 0xb7, 0xfa, 0x08, 0x2f, 0xef, 0x30, 0x78, 0x22, 0x11, 0x93, 0x8b, 0xc1, 0xc5, 0xe7, 0x04, 0x16, 0xff, 0x44},
		Truncated:            0x82fef30,
		OTP:                  359152,
	},
	{
		Counter:              3,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0x66, 0xc2, 0x82, 0x27, 0xd0, 0x3a, 0x2d, 0x55, 0x29, 0x26, 0x2f, 0xf0, 0x16, 0xa1, 0xe6, 0xef, 0x76, 0x55, 0x7e, 0xce},
		Truncated:            0x66ef7655,
		OTP:                  969429,
	},
	{
		Counter:              4,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0xa9, 0x04, 0xc9, 0x00, 0xa6, 0x4b, 0x35, 0x90, 0x98, 0x74, 0xb3, 0x3e, 0x61, 0xc5, 0x93, 0x8a, 0x8e, 0x15, 0xed, 0x1c},
		Truncated:            0x61c5938a,
		OTP:                  338314,
	},
	{
		Counter:              5,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0xa3, 0x7e, 0x78, 0x3d, 0x7b, 0x72, 0x33, 0xc0, 0x83, 0xd4, 0xf6, 0x29, 0x26, 0xc7, 0xa2, 0x5f, 0x23, 0x8d, 0x03, 0x16},
		Truncated:            0x33c083d4,
		OTP:                  254676,
	},
	{
		Counter:              6,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0xbc, 0x9c, 0xd2, 0x85, 0x61, 0x04, 0x2c, 0x83, 0xf2, 0x19, 0x32, 0x4d, 0x3c, 0x60, 0x72, 0x56, 0xc0, 0x32, 0x72, 0xae},
		Truncated:            0x7256c032,
		OTP:                  287922,
	},
	{
		Counter:              7,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0xa4, 0xfb, 0x96, 0x0c, 0x0b, 0xc0, 0x6e, 0x1e, 0xab, 0xb8, 0x04, 0xe5, 0xb3, 0x97, 0xcd, 0xc4, 0xb4, 0x55, 0x96, 0xfa},
		Truncated:            0x4e5b397,
		OTP:                  162583,
	},
	{
		Counter:              8,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0x1b, 0x3c, 0x89, 0xf6, 0x5e, 0x6c, 0x9e, 0x88, 0x30, 0x12, 0x05, 0x28, 0x23, 0x44, 0x3f, 0x04, 0x8b, 0x43, 0x32, 0xdb},
		Truncated:            0x2823443f,
		OTP:                  399871,
	},
	{
		Counter:              9,
		Secret:               hotpSecret,
		IntermediateHmacSha1: []byte{0x16, 0x37, 0x40, 0x98, 0x09, 0xa6, 0x79, 0xdc, 0x69, 0x82, 0x07, 0x31, 0x0c, 0x8c, 0x7f, 0xc0, 0x72, 0x90, 0xd9, 0xe5},
		Truncated:            0x2679dc69,
		OTP:                  520489,
	},
}

func TestHmacShaN1(t *testing.T) {
	for _, testValue := range hotpTestValues {
		res := hmacShaN(sha1.New, testValue.Secret, testValue.Counter)
		if !bytes.Equal(res, testValue.IntermediateHmacSha1) {
			t.Errorf("Error in hmacSha1 for Counter = %d", testValue.Counter)
		}
	}
}

func TestDynamicTruncation(t *testing.T) {
	for _, testValue := range hotpTestValues {
		res := dynamicTruncation(testValue.IntermediateHmacSha1)
		if res != testValue.Truncated {
			t.Errorf("Error in dynamicTruncation for Counter = %d (expected %d, got %d)", testValue.Counter, testValue.Truncated, res)
		}
	}
}

func TestHOTP(t *testing.T) {
	for _, testValue := range hotpTestValues {
		res := HOTP(testValue.Secret, testValue.Counter, HOTPOptions{})
		if res != testValue.OTP {
			t.Errorf("Error in Compute for Counter = %d (expected %d, got %d)", testValue.Counter, testValue.OTP, res)
		}
	}
}

func TestHOTPDefaults(t *testing.T) {
	testValue := hotpTestValues[0]

	resDefaults := HOTP(testValue.Secret, testValue.Counter, HOTPOptions{})
	resCustom := HOTP(testValue.Secret, testValue.Counter, HOTPOptions{
		Digits:    6,
		Algorithm: sha1.New,
	})

	if resDefaults != resCustom {
		t.Errorf("Error in HOTPDefaults (expected = %d, got = %d)", resCustom, resDefaults)
	}
}
