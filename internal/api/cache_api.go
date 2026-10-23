package api

import (
	"net/http"

	"proxygo/internal/respcache"
)

// cache_api.go — Feature Pack F1 dashboard endpoints for the response
// cache: GET /api/cache/stats and POST /api/cache/clear.
//
// Guard note: /api/cache is not (yet) in api.go's protectedPrefixes,
// so these handlers enforce the same dashboard-session rule themselves
// (RequireAuth's protected-prefix semantics: when the requireLogin
// setting is on — the default — a valid session token is required).
// They are additionally wrapped in Wrap like every other registrar, so
// if /api/cache joins the prefix list the checks simply agree.
//
// Parent wires this with one line in RegisterAll:
//
//	RegisterCacheAPI(mux, deps)

// RegisterCacheAPI mounts the response-cache dashboard routes.
func RegisterCacheAPI(mux *http.ServeMux, deps Deps) {
	w := func(h http.HandlerFunc) http.HandlerFunc {
		return Wrap(deps, cacheSessionGuard(deps, h))
	}
	mux.HandleFunc("GET /api/cache/stats", w(cacheStatsHandler))
	mux.HandleFunc("POST /api/cache/clear", w(cacheClearHandler))
}

// cacheSessionGuard mirrors RequireAuth's protected-prefix branch.
func cacheSessionGuard(deps Deps, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Store != nil && VerifySessionToken(deps.Store, SessionToken(r)) {
			h(w, r)
			return
		}
		requireLogin := true
		if deps.Store != nil {
			if settings, err := deps.Store.GetSettings(); err == nil && settings != nil {
				if v, ok := settings["requireLogin"].(bool); ok {
					requireLogin = v
				}
			}
		}
		if requireLogin {
			Err(w, http.StatusUnauthorized, "Unauthorized")
			return
		}
		h(w, r)
	}
}

func cacheStatsHandler(w http.ResponseWriter, r *http.Request) {
	enabled, ttlSeconds, maxEntries := respcache.Config()
	s := respcache.StatsSnapshot()
	var hitRate float64
	if total := s.Hits + s.Misses; total > 0 {
		hitRate = float64(s.Hits) / float64(total)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"enabled":    enabled,
		"ttlSeconds": ttlSeconds,
		"maxEntries": maxEntries,
		"hits":       s.Hits,
		"misses":     s.Misses,
		"stores":     s.Stores,
		"evictions":  s.Evictions,
		"entries":    s.Entries,
		"hitRate":    hitRate,
	})
}

func cacheClearHandler(w http.ResponseWriter, r *http.Request) {
	respcache.Clear()
	WriteJSON(w, http.StatusOK, map[string]any{
		"cleared": true,
		"entries": respcache.StatsSnapshot().Entries,
	})
}
