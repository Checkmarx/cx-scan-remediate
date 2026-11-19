// Package errlog records the non-fatal operational failures of a run (triage, remediation, patch
// or pull request errors), so that the run can carry on and still exit with an error code.
package errlog

import "github.com/sirupsen/logrus"

// Recorder logs each failure at error level and counts it.
type Recorder struct {
	logger *logrus.Logger
	count  int
}

// New returns a Recorder that logs to logger.
func New(logger *logrus.Logger) *Recorder {
	return &Recorder{logger: logger}
}

// Errorf logs a failure and counts it.
func (r *Recorder) Errorf(format string, args ...interface{}) {
	r.count++
	r.logger.Errorf(format, args...)
}

// Count is the number of failures recorded so far.
func (r *Recorder) Count() int { return r.count }
