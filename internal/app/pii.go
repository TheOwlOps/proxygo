package app

import (
	"proxygo/internal/chatcore"
	"proxygo/internal/pii"
)

// piiGuardImpl adapts internal/pii to chatcore's BodyGuard hook.
// pii.RedactBody is fail-open: it mutates the body in place when
// enabled and never fails the request.
//
// The chatcore.BodyGuard signature only carries the master `enabled`
// flag (settings key piiRedactionEnabled, applied by chatcore from its
// Settings). The second opt-in — redacting 12-digit VN national IDs
// (settings key piiRedactNationalId, default off) — has no channel in
// that signature, so it is captured here at construction (wire) time:
// the parent reads piiRedactNationalId from the settings doc when
// building the Service and passes it to NewPIIGuard. Changing the
// setting therefore takes effect on the next Service rebuild/restart,
// unlike piiRedactionEnabled, which chatcore reads live per request.
type piiGuardImpl struct {
	nationalID bool
}

// Process implements chatcore.BodyGuard.
func (g piiGuardImpl) Process(body map[string]any, format string, enabled bool) int {
	if !enabled {
		return 0
	}
	return pii.RedactBody(body, pii.Options{NationalID: g.nationalID})
}

// PIIGuardImpl returns the PII BodyGuard with default options
// (national-ID redaction off).
func PIIGuardImpl() chatcore.BodyGuard { return piiGuardImpl{} }

// NewPIIGuard returns the PII BodyGuard with the national-ID opt-in
// captured from settings at wire time (see piiGuardImpl).
func NewPIIGuard(nationalID bool) chatcore.BodyGuard {
	return piiGuardImpl{nationalID: nationalID}
}

// WirePIIGuard attaches the default PII BodyGuard to an already-built
// chatcore.Service. NewService sets the field directly; this helper
// exists for code paths that construct a Service themselves (tests,
// future server variants).
func WirePIIGuard(s *chatcore.Service) {
	if s != nil {
		s.BodyGuard = PIIGuardImpl()
	}
}

// WirePIIGuardWith is WirePIIGuard with the national-ID opt-in captured
// from settings at wire time.
func WirePIIGuardWith(s *chatcore.Service, nationalID bool) {
	if s != nil {
		s.BodyGuard = NewPIIGuard(nationalID)
	}
}
