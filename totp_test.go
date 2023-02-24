package otp

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"testing"
	"time"
)

type TOTPTestValue struct {
	Time          time.Time
	Mode          func() hash.Hash
	Digits        uint
	TimeReference int64
	Period        int
	Secret        []byte
	T             int
	OTP           uint
}

var totpSecretSha1 []byte = []byte("12345678901234567890")
var totpSecretSha256 []byte = []byte("12345678901234567890123456789012")
var totpSecretSha512 []byte = []byte("1234567890123456789012345678901234567890123456789012345678901234")

var totpTestValues []TOTPTestValue = []TOTPTestValue{
	{
		Time:          time.Unix(59, 0),
		Mode:          sha1.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha1,
		T:             0x0000000000000001,
		OTP:           94287082,
	},
	{
		Time:          time.Unix(59, 0),
		Mode:          sha256.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha256,
		T:             0x0000000000000001,
		OTP:           46119246,
	},
	{
		Time:          time.Unix(59, 0),
		Mode:          sha512.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha512,
		T:             0x0000000000000001,
		OTP:           90693936,
	},
	{
		Time:          time.Unix(1111111109, 0),
		Mode:          sha1.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha1,
		T:             0x00000000023523EC,
		OTP:           7081804,
	},
	{
		Time:          time.Unix(1111111109, 0),
		Mode:          sha256.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha256,
		T:             0x00000000023523EC,
		OTP:           68084774,
	},
	{
		Time:          time.Unix(1111111109, 0),
		Mode:          sha512.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha512,
		T:             0x00000000023523EC,
		OTP:           25091201,
	},
	{
		Time:          time.Unix(1111111111, 0),
		Mode:          sha1.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		T:             0x00000000023523ED,
		OTP:           14050471,
		Secret:        totpSecretSha1,
	},
	{
		Time:          time.Unix(1111111111, 0),
		Mode:          sha256.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha256,
		T:             0x00000000023523ED,
		OTP:           67062674,
	},
	{
		Time:          time.Unix(1111111111, 0),
		Mode:          sha512.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha512,
		T:             0x00000000023523ED,
		OTP:           99943326,
	},
	{
		Time:          time.Unix(1234567890, 0),
		Mode:          sha1.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha1,
		T:             0x000000000273EF07,
		OTP:           89005924,
	},
	{
		Time:          time.Unix(1234567890, 0),
		Mode:          sha256.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha256,
		T:             0x000000000273EF07,
		OTP:           91819424,
	},
	{
		Time:          time.Unix(1234567890, 0),
		Mode:          sha512.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha512,
		T:             0x000000000273EF07,
		OTP:           93441116,
	},
	{
		Time:          time.Unix(2000000000, 0),
		Mode:          sha1.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha1,
		T:             0x0000000003F940AA,
		OTP:           69279037,
	},
	{
		Time:          time.Unix(2000000000, 0),
		Mode:          sha256.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha256,
		T:             0x0000000003F940AA,
		OTP:           90698825,
	},
	{
		Time:          time.Unix(2000000000, 0),
		Mode:          sha512.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha512,
		T:             0x0000000003F940AA,
		OTP:           38618901,
	},
	{
		Time:          time.Unix(20000000000, 0),
		Mode:          sha1.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha1,
		T:             0x0000000027BC86AA,
		OTP:           65353130,
	},
	{
		Time:          time.Unix(20000000000, 0),
		Mode:          sha256.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha256,
		T:             0x0000000027BC86AA,
		OTP:           77737706,
	},
	{
		Time:          time.Unix(20000000000, 0),
		Mode:          sha512.New,
		Digits:        8,
		TimeReference: 0,
		Period:        30,
		Secret:        totpSecretSha512,
		T:             0x0000000027BC86AA,
		OTP:           47863826,
	},
}

func TestTimePeriodCount(t *testing.T) {
	for i, testValue := range totpTestValues {
		res := timePeriodCount(testValue.Time.Unix(), testValue.TimeReference, testValue.Period)
		if res != testValue.T {
			t.Errorf("Error in TimePeriodCount (i = %d, expected = %d, got = %d)", i, testValue.T, res)
		}
	}
}

func TestTOTP(t *testing.T) {
	for i, testValue := range totpTestValues {
		res := TOTP(testValue.Secret, testValue.Time, TOTPOptions{
			HOTPOptions: HOTPOptions{
				Digits:   testValue.Digits,
				HashFunc: testValue.Mode,
			},
			TimeReference: testValue.TimeReference,
			Period:        testValue.Period,
			Step:          0,
		})
		if res != testValue.OTP {
			t.Errorf("Error in Compute (i = %d, expected = %d, got = %d)", i, testValue.OTP, res)
		}
	}
}

func TestTimePeriodCountStep(t *testing.T) {
	steps := []int{-2, -1, 0, 1, 2}
	for i, testValue := range totpTestValues {
		for _, step := range steps {
			res := timePeriodCount(testValue.Time.Add(time.Second*time.Duration(testValue.Period)*time.Duration(step)).Unix(), testValue.TimeReference, testValue.Period)
			expected := testValue.T + step
			if res != expected {
				t.Errorf("Error in TimePeriodCountStep (i = %d, step = %d, expected = %d, got = %d)", i, step, expected, res)
			}
		}
	}
}

func TestTOTPStep(t *testing.T) {
	steps := []int{-2, -1, 0, 1, 2}
	for i, testValue := range totpTestValues {
		for _, step := range steps {
			resAdd := TOTP(testValue.Secret, testValue.Time.Add(time.Duration(testValue.Period)*time.Second*time.Duration(step)), TOTPOptions{
				HOTPOptions: HOTPOptions{
					Digits:   testValue.Digits,
					HashFunc: testValue.Mode,
				},
				TimeReference: testValue.TimeReference,
				Period:        testValue.Period,
				Step:          0,
			})
			resStep := TOTP(testValue.Secret, testValue.Time, TOTPOptions{
				HOTPOptions: HOTPOptions{
					Digits:   testValue.Digits,
					HashFunc: testValue.Mode,
				},
				TimeReference: testValue.TimeReference,
				Period:        testValue.Period,
				Step:          step,
			})
			if resStep != resAdd {
				t.Errorf("Error in ComputeStep (i = %d, step = %d, expected = %d, got = %d)", i, step, resAdd, resStep)
			}
		}
	}
}
