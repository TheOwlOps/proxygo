package api

import (
	"math"
	"net/http"
	"time"

	"proxygo/internal/db"
	"proxygo/internal/keylimit"
)

// Feature Pack F3 — per-API-key limits management:
//   GET    /api/keys/{id}/limits         read the limits document
//   PUT    /api/keys/{id}/limits         replace it (0 = unlimited)
//   DELETE /api/keys/{id}/limits         remove it (back to unlimited)
//   GET    /api/keys/{id}/usage-summary  today's + this month's totals
//
// The parent registers RegisterKeyLimitsAPI from RegisterAll; all
// routes sit behind the dashboard session guard like the other /api
// key routes. Limits take effect on the next chat request (the
// chatcore KeyLimiter reads them per request).

func RegisterKeyLimitsAPI(mux *http.ServeMux, deps Deps) {
	mux.HandleFunc("GET /api/keys/{id}/limits", Wrap(deps, keyLimitsGet(deps)))
	mux.HandleFunc("PUT /api/keys/{id}/limits", Wrap(deps, keyLimitsPut(deps)))
	mux.HandleFunc("DELETE /api/keys/{id}/limits", Wrap(deps, keyLimitsDelete(deps)))
	mux.HandleFunc("GET /api/keys/{id}/usage-summary", Wrap(deps, keyUsageSummary(deps)))
}

// keyLimitsKey resolves the {id} path value to a key record, writing
// the error response and returning nil when it does not exist.
func keyLimitsKey(deps Deps, w http.ResponseWriter, r *http.Request) db.Record {
	rec, err := deps.Store.GetAPIKeyByID(r.PathValue("id"))
	if err != nil {
		Err(w, http.StatusInternalServerError, "Failed to fetch key")
		return nil
	}
	if rec == nil {
		Err(w, http.StatusNotFound, "Key not found")
		return nil
	}
	return rec
}

func keyLimitsGet(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := keyLimitsKey(deps, w, r)
		if rec == nil {
			return
		}
		lim, err := keylimit.GetLimits(deps.Store, Str(rec, "id"))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch key limits")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"keyId": Str(rec, "id"), "limits": lim})
	}
}

// parseLimitsInput validates a limits document from a decoded JSON
// body: the flat object {rpm, dailyTokens, ...} or the same object
// wrapped under "limits". Missing fields mean 0 (unlimited).
func parseLimitsInput(body map[string]any) (keylimit.Limits, string) {
	src := body
	if wrapped, ok := body["limits"].(map[string]any); ok {
		src = wrapped
	}
	var lim keylimit.Limits
	intField := func(name string, dst *int64) string {
		v, present := src[name]
		if !present || v == nil {
			return ""
		}
		f, ok := v.(float64)
		if !ok || f < 0 || f != math.Trunc(f) {
			return name + " must be a non-negative integer"
		}
		*dst = int64(f)
		return ""
	}
	costField := func(name string, dst *float64) string {
		v, present := src[name]
		if !present || v == nil {
			return ""
		}
		f, ok := v.(float64)
		if !ok || f < 0 {
			return name + " must be a non-negative number"
		}
		*dst = f
		return ""
	}
	for _, step := range []func() string{
		func() string { return intField("rpm", &lim.RPM) },
		func() string { return intField("dailyTokens", &lim.DailyTokens) },
		func() string { return intField("monthlyTokens", &lim.MonthlyTokens) },
		func() string { return costField("dailyCostUSD", &lim.DailyCostUSD) },
		func() string { return costField("monthlyCostUSD", &lim.MonthlyCostUSD) },
	} {
		if msg := step(); msg != "" {
			return keylimit.Limits{}, msg
		}
	}
	return lim, ""
}

func keyLimitsPut(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := keyLimitsKey(deps, w, r)
		if rec == nil {
			return
		}
		body, err := ReadBodyJSON(r)
		if err != nil {
			Err(w, http.StatusBadRequest, "Invalid JSON body")
			return
		}
		lim, msg := parseLimitsInput(body)
		if msg != "" {
			Err(w, http.StatusBadRequest, msg)
			return
		}
		id := Str(rec, "id")
		if err := keylimit.SetLimits(deps.Store, id, lim); err != nil {
			Err(w, http.StatusInternalServerError, "Failed to save key limits")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"keyId": id, "limits": lim})
	}
}

func keyLimitsDelete(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := keyLimitsKey(deps, w, r)
		if rec == nil {
			return
		}
		if err := keylimit.DeleteLimits(deps.Store, Str(rec, "id")); err != nil {
			Err(w, http.StatusInternalServerError, "Failed to delete key limits")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"success": true})
	}
}

func keyUsageTotalsRecord(t db.KeyUsageTotals) map[string]any {
	return map[string]any{
		"requests":         t.Requests,
		"promptTokens":     t.PromptTokens,
		"completionTokens": t.CompletionTokens,
		"totalTokens":      t.TotalTokens,
		"costUSD":          t.CostUSD,
	}
}

func keyUsageSummary(deps Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := keyLimitsKey(deps, w, r)
		if rec == nil {
			return
		}
		id := Str(rec, "id")
		keyStr := Str(rec, "key")
		lim, err := keylimit.GetLimits(deps.Store, id)
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch key limits")
			return
		}
		now := time.Now()
		today, err := deps.Store.GetKeyUsageTotals(keyStr, keylimit.StartOfDay(now))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch key usage")
			return
		}
		month, err := deps.Store.GetKeyUsageTotals(keyStr, keylimit.StartOfMonth(now))
		if err != nil {
			Err(w, http.StatusInternalServerError, "Failed to fetch key usage")
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"keyId":  id,
			"limits": lim,
			"today":  keyUsageTotalsRecord(today),
			"month":  keyUsageTotalsRecord(month),
		})
	}
}
