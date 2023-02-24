// totp implements TOTP as described in rfc 6238 (https://www.ietf.org/rfc/rfc6238.txt).
package totp

import (
	"time"

	"github.com/xrjr/otp/hotp"
)

// Client contains base informations required to compute TOTP code.
type Client struct {
	HOTPClient hotp.Client
	T0         int64 // reference time in seconds
	TimeStepX  int   // time period in seconds
}

// New returns a TOTP client with a given key.
// Default options are used : T0 = 0, TimeStepX = 30. You can access and change those options.
// A default hotp.Client is used in background, you can access and change its options.
func New(key []byte) Client {
	return Client{
		HOTPClient: hotp.New(key),
		T0:         0,
		TimeStepX:  30,
	}
}

// Compute computes the OTP code of a given time.
func (c Client) Compute(t time.Time) uint {
	return c.HOTPClient.Compute(TimePeriodCount(t.Unix(), c.T0, c.TimeStepX))
}

// ComputeStep does the same as Compute, but n time periods before or forwads (can be negative).
// It is typically used in server context, where you might want to compute one step behind because of transmission delay.
// It is described in the 5.2 section of the rfc.
func (c Client) ComputeStep(t time.Time, n int) uint {
	return c.HOTPClient.Compute(TimePeriodCount(t.Unix(), c.T0, c.TimeStepX) + n)
}

// TimePeriodCount returns T as defined in section 4.2 of the rfc.
func TimePeriodCount(currentTime int64, t0 int64, x int) int {
	if currentTime < t0 {
		return int((currentTime-t0)/int64(x)) - 1
	}
	return int((currentTime - t0) / int64(x))
}
