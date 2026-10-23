// 9Router — Go port. Backend in Go, React dashboard served as static
// files (WEB_DIR). Env contract mirrors the original .env.example:
// PORT (default 20128), DATA_DIR (else ~/.9router/), WEB_DIR,
// UPSTREAM_API_KEY / UPSTREAM_BASE_URL (optional first-run seed for an
// "openai" connection, only when the DB has no connections yet).
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"9router-go/internal/db"
	"9router-go/internal/server"
)

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func main() {
	store, err := db.Open()
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	// Legacy db.json/usage.json import (Phase 2, Team J): runs once, only
	// when the SQLite tables are empty; a no-op otherwise.
	if _, err := store.ImportLegacyJSONOnce(); err != nil {
		log.Printf("legacy import: %v", err)
	}
	seedFromEnv(store)

	port := env("PORT", "20128")
	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           server.New(store),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("9router-go listening on :%s (data dir %s)", port, store.Dir())
	log.Fatal(srv.ListenAndServe())
}

// seedFromEnv preserves the pre-port scaffold's behaviour: with
// UPSTREAM_API_KEY set and an empty connections table, create one
// "openai" apikey connection so a fresh install can chat immediately.
func seedFromEnv(store *db.Store) {
	key := os.Getenv("UPSTREAM_API_KEY")
	if key == "" {
		return
	}
	conns, err := store.GetProviderConnections(db.ConnectionFilter{})
	if err != nil || len(conns) > 0 {
		return
	}
	rec := db.Record{
		"provider": "openai", "authType": "apikey", "name": "env",
		"apiKey": key, "isActive": true,
	}
	if base := strings.TrimRight(os.Getenv("UPSTREAM_BASE_URL"), "/"); base != "" {
		// Registry baseUrl already ends at /chat/completions; a seed base
		// URL ending in /v1 needs the suffix the executor would append.
		if strings.HasSuffix(base, "/v1") {
			base += "/chat/completions"
		}
		rec["providerSpecificData"] = map[string]any{"baseUrl": base}
	}
	if _, err := store.CreateProviderConnection(rec); err != nil {
		log.Printf("seed connection: %v", err)
		return
	}
	log.Printf("seeded openai connection from UPSTREAM_API_KEY")
}
