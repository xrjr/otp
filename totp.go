package otp

import (
	"time"
)

type TOTPOptions struct {
	HOTPOptions
	TimeReference int64 // time reference in seconds (called T0 in rfc)
	Period        int   // time period in seconds (called X in rfc)
	Step          int   // number of step before or after given time
}

// TOTP computes the OTP code of a given time.
func TOTP(key []byte, t time.Time, opts TOTPOptions) uint {
	// defaults
	// opts.TimeReference and opts.Step both default to 0
	if opts.Period == 0 {
		opts.Period = 30
	}

	// Compute
	return HOTP(key, timePeriodCounter(t.Unix(), opts.TimeReference, opts.Period)+opts.Step, opts.HOTPOptions)
}

// timePeriodCounter returns T as defined in section 4.2 of the rfc.
func timePeriodCounter(currentTime int64, t0 int64, x int) int {
	if currentTime < t0 {
		return int((currentTime-t0)/int64(x)) - 1
	}
	return int((currentTime - t0) / int64(x))
}
