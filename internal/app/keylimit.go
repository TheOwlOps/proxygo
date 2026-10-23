package app

import (
	"proxygo/internal/chatcore"
	"proxygo/internal/db"
	"proxygo/internal/keylimit"
)

// KeyLimiterImpl builds the Feature Pack F3 per-key rate-limit /
// budget enforcer over the store. Limits are read from the KV store
// per request (keylimit:<apiKeyId>), so dashboard changes take effect
// without a restart; a key with no limits is never rejected.
func KeyLimiterImpl(store *db.Store) chatcore.KeyLimiter {
	return keylimit.New(store)
}

// WireKeyLimiter attaches the key limiter to an already-built
// chatcore.Service. The parent calls this in NewService; the helper
// also serves code paths that construct a Service themselves.
func WireKeyLimiter(s *chatcore.Service, store *db.Store) {
	if s != nil {
		s.KeyLimiter = KeyLimiterImpl(store)
	}
}
