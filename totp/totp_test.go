package totp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"
)

type TestValue struct {
	Time   time.Time
	Mode   func() hash.Hash
	Secret []byte
	T      int
	OTP    uint
}

var SecretSha1 []byte = []byte("12345678901234567890")
var SecretSha256 []byte = []byte("12345678901234567890123456789012")
var SecretSha512 []byte = []byte("1234567890123456789012345678901234567890123456789012345678901234")

var Digits uint = 8

var T0 int64 = 0

var TimeStepX = 30

var testValues []TestValue = []TestValue{
	{
		Time:   time.Unix(59, 0),
		Mode:   sha1.New,
		Secret: SecretSha1,
		T:      0x0000000000000001,
		OTP:    94287082,
	},
	{
		Time:   time.Unix(59, 0),
		Mode:   sha256.New,
		Secret: SecretSha256,
		T:      0x0000000000000001,
		OTP:    46119246,
	},
	{
		Time:   time.Unix(59, 0),
		Mode:   sha512.New,
		Secret: SecretSha512,
		T:      0x0000000000000001,
		OTP:    90693936,
	},
	{
		Time:   time.Unix(1111111109, 0),
		Mode:   sha1.New,
		Secret: SecretSha1,
		T:      0x00000000023523EC,
		OTP:    7081804,
	},
	{
		Time:   time.Unix(1111111109, 0),
		Mode:   sha256.New,
		Secret: SecretSha256,
		T:      0x00000000023523EC,
		OTP:    68084774,
	},
	{
		Time:   time.Unix(1111111109, 0),
		Mode:   sha512.New,
		Secret: SecretSha512,
		T:      0x00000000023523EC,
		OTP:    25091201,
	},
	{
		Time:   time.Unix(1111111111, 0),
		Mode:   sha1.New,
		T:      0x00000000023523ED,
		OTP:    14050471,
		Secret: SecretSha1,
	},
	{
		Time:   time.Unix(1111111111, 0),
		Mode:   sha256.New,
		Secret: SecretSha256,
		T:      0x00000000023523ED,
		OTP:    67062674,
	},
	{
		Time:   time.Unix(1111111111, 0),
		Mode:   sha512.New,
		Secret: SecretSha512,
		T:      0x00000000023523ED,
		OTP:    99943326,
	},
	{
		Time:   time.Unix(1234567890, 0),
		Mode:   sha1.New,
		Secret: SecretSha1,
		T:      0x000000000273EF07,
		OTP:    89005924,
	},
	{
		Time:   time.Unix(1234567890, 0),
		Mode:   sha256.New,
		Secret: SecretSha256,
		T:      0x000000000273EF07,
		OTP:    91819424,
	},
	{
		Time:   time.Unix(1234567890, 0),
		Mode:   sha512.New,
		Secret: SecretSha512,
		T:      0x000000000273EF07,
		OTP:    93441116,
	},
	{
		Time:   time.Unix(2000000000, 0),
		Mode:   sha1.New,
		Secret: SecretSha1,
		T:      0x0000000003F940AA,
		OTP:    69279037,
	},
	{
		Time:   time.Unix(2000000000, 0),
		Mode:   sha256.New,
		Secret: SecretSha256,
		T:      0x0000000003F940AA,
		OTP:    90698825,
	},
	{
		Time:   time.Unix(2000000000, 0),
		Mode:   sha512.New,
		Secret: SecretSha512,
		T:      0x0000000003F940AA,
		OTP:    38618901,
	},
	{
		Time:   time.Unix(20000000000, 0),
		Mode:   sha1.New,
		Secret: SecretSha1,
		T:      0x0000000027BC86AA,
		OTP:    65353130,
	},
	{
		Time:   time.Unix(20000000000, 0),
		Mode:   sha256.New,
		Secret: SecretSha256,
		T:      0x0000000027BC86AA,
		OTP:    77737706,
	},
	{
		Time:   time.Unix(20000000000, 0),
		Mode:   sha512.New,
		Secret: SecretSha512,
		T:      0x0000000027BC86AA,
		OTP:    47863826,
	},
}

func TestTimePeriodCount(t *testing.T) {
	for i, testValue := range testValues {
		res := TimePeriodCount(testValue.Time.Unix(), T0, TimeStepX)
		if res != testValue.T {
			t.Errorf("Error in TimePeriodCount (i = %d, expected = %d, got = %d)", i, testValue.T, res)
		}
	}
}

func TestCompute(t *testing.T) {
	for i, testValue := range testValues {
		client := New(testValue.Secret)
		client.HOTPClient.Digits = 8
		client.HOTPClient.HashFunc = testValue.Mode
		res := client.Compute(testValue.Time)
		if res != testValue.OTP {
			t.Errorf("Error in Compute (i = %d, expected = %d, got = %d)", i, testValue.OTP, res)
		}
	}
}

func TestTimePeriodCountStep(t *testing.T) {
	steps := []int{-2, -1, 0, 1, 2}
	for i, testValue := range testValues {
		for _, step := range steps {
			res := TimePeriodCount(testValue.Time.Add(time.Second*time.Duration(TimeStepX)*time.Duration(step)).Unix(), T0, TimeStepX)
			expected := testValue.T + step
			if res != expected {
				t.Errorf("Error in TimePeriodCountStep (i = %d, step = %d, expected = %d, got = %d)", i, step, expected, res)
			}
		}
	}
}

func TestComputeStep(t *testing.T) {
	steps := []int{-2, -1, 0, 1, 2}
	for i, testValue := range testValues {
		client := New(testValue.Secret)
		client.HOTPClient.Digits = 8
		client.HOTPClient.HashFunc = testValue.Mode

		for _, step := range steps {
			res := client.Compute(testValue.Time.Add(time.Duration(TimeStepX) * time.Second * time.Duration(step)))
			resStep := client.ComputeStep(testValue.Time, step)
			if resStep != res {
				t.Errorf("Error in ComputeStep (i = %d, step = %d, expected = %d, got = %d)", i, step, res, resStep)
			}
		}
	}
}
