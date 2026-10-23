package app

import (
	"proxygo/internal/chatcore"
	"proxygo/internal/rtk"
)

// tokenSaverImpl adapts internal/rtk (the open-sse/rtk port) to
// chatcore's TokenSaver hook. rtk.CompressMessages is fail-open: it
// mutates the body in place when enabled and never fails the request.
type tokenSaverImpl struct{}

// Compress implements chatcore.TokenSaver. The format argument is
// accepted for interface parity — the JS compressMessages(body, enabled)
// ignores it (RTK runs on the body as-is, before translation).
func (tokenSaverImpl) Compress(body map[string]any, format string, enabled bool) {
	_ = rtk.CompressMessages(body, enabled)
}

// TokenSaverImpl returns the RTK-backed chatcore.TokenSaver.
func TokenSaverImpl() chatcore.TokenSaver { return tokenSaverImpl{} }

// WireTokenSaver attaches the RTK TokenSaver to an already-built
// chatcore.Service. NewService sets the field directly; this helper
// exists for code paths that construct a Service themselves (tests,
// future server variants).
func WireTokenSaver(s *chatcore.Service) {
	if s != nil {
		s.TokenSaver = TokenSaverImpl()
	}
}
