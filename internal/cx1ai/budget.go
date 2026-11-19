package cx1ai

import (
	"math"
	"time"
)

// Budget is the overall time allowance for the AI Triage and AI Remediation phases of a run.
// A zero end means no limit. Publishing a pull request is never cut short by the budget: a
// remediation that has already been generated (and paid for) is always published.
type Budget struct {
	end time.Time
}

// NewBudget starts a budget of d from now; d <= 0 means no limit.
func NewBudget(d time.Duration) Budget {
	if d <= 0 {
		return Budget{}
	}
	return Budget{end: time.Now().Add(d)}
}

func (b Budget) Unlimited() bool { return b.end.IsZero() }

func (b Budget) Remaining() time.Duration {
	if b.Unlimited() {
		return time.Duration(math.MaxInt64)
	}
	return time.Until(b.end)
}

func (b Budget) Expired() bool { return !b.Unlimited() && b.Remaining() <= 0 }

// pollTimeouts returns the delay and maximum, in seconds, to pass to a library polling call:
// the library's own maximum, or the time remaining if that is smaller. The result is at least
// one second, so once the budget is spent a poll is still a quick check whether the job has
// already finished. A library maximum of 0 means "no limit" and is replaced by the remaining
// time when a budget is set. The delay is capped to the maximum so the library's retry sleep
// cannot overshoot the budget by a whole delay interval.
func (b Budget) PollTimeouts(libDelay, libMax int) (delay, max int) {
	if b.Unlimited() {
		return libDelay, libMax
	}
	rem := int(math.Ceil(b.Remaining().Seconds()))
	if rem < 1 {
		rem = 1
	}
	max = libMax
	if max == 0 || rem < max {
		max = rem
	}
	delay = libDelay
	if delay > max {
		delay = max
	}
	if delay < 1 {
		delay = 1
	}
	return delay, max
}
