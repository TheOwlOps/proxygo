package api

import (
	"net/http"

	"9router-go/internal/db"
)

// RegisterBreakerAPI mounts the Feature Pack F2 circuit-breaker stats
// route. The parent adds the call in RegisterAll.
//
// GET /api/breaker/stats → {enabled, circuits: [breaker.KeyStats...]}
// backed by Deps.Chat.BreakerSnapshot(). When no breaker is wired the
// response stays sane: {enabled:false, circuits:[]}.
func RegisterBreakerAPI(mux *http.ServeMux, deps Deps) {
	w := func(h http.HandlerFunc) http.HandlerFunc { return Wrap(deps, h) }
	mux.HandleFunc("GET /api/breaker/stats", w(breakerStats(deps)))
}

func breakerStats(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var snap any
		if deps.Chat != nil {
			snap = deps.Chat.BreakerSnapshot()
		}
		if snap == nil {
			WriteJSON(w, http.StatusOK, db.Record{
				"enabled":  false,
				"circuits": []any{},
			})
			return
		}
		WriteJSON(w, http.StatusOK, db.Record{
			"enabled":  true,
			"circuits": snap,
		})
	}
}
