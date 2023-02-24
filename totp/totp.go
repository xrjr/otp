package totp

import (
	"time"

	"github.com/xrjr/otp/hotp"
)

// Client contains base informations required to compute TOTP code.
// Its underlying hotp.Client can be configured for example to change the number of digits returned.
type Client struct {
	HOTPClient hotp.Client
	T0         int64 // reference time in seconds
	TimeStepX  int   // time period in seconds
}

func New(key []byte) Client {
	return Client{
		HOTPClient: hotp.New(key),
		T0:         0,
		TimeStepX:  30,
	}
}

// Compute computes the OTP code of a given time.
func (c Client) Compute(t time.Time) uint {
	return c.HOTPClient.Compute(timePeriodCount(t.Unix(), c.T0, c.TimeStepX))
}

// ComputeStep does the same as Compute, but n time periods before or forwads (can be negative).
// It is typically used in server context, where you might want to compute one step behind because of transmission delay.
// It is described in the 5.2 section of the rfc.
func (c Client) ComputeStep(t time.Time, n int) uint {
	return c.HOTPClient.Compute(timePeriodCount(t.Unix(), c.T0, c.TimeStepX) + n)
}

// timePeriodCount returns T as defined in section 4.2 of the rfc.
func timePeriodCount(currentTime int64, t0 int64, x int) int {
	if currentTime < t0 {
		return int((currentTime-t0)/int64(x)) - 1
	}
	return int((currentTime - t0) / int64(x))
}
