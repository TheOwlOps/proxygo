package app

// Phase 2 — Team K wiring: model catalogue + pricing hooks.
//
// This file is the ONLY app-package file Team K adds; the ModelMeta
// enrichment itself is a minimal, flagged edit inside app.go's
// providerSource.ModelMeta (it consults internal/modelcatalog first and
// keeps the phase-1 registry-Kind fallback).
//
// Pricing hooks: internal/db exposes package-level vars
// (db.DefaultProviderPricing, db.PricingResolver) that Team C left for
// the parent to wire. WireCatalog sets them from the extracted pricing
// tables (open-sse/providers/pricing.js). The hooks are process-global
// in the JS design too (pricingRepo merges a module-level catalogue),
// so WireCatalog's store parameter is accepted for symmetry with the
// other wiring entry points but not needed — wiring is therefore safe
// to perform from init(), and init() below does exactly that. Tests and
// alternative mains may call WireCatalog again; it is idempotent.

import (
	"9router-go/internal/db"
	"9router-go/internal/modelcatalog"
)

// WireCatalog installs the extracted pricing catalogue into the db
// package hooks: DefaultProviderPricing = PROVIDER_PRICING, and
// PricingResolver = the ported getPricingForModel fallback chain
// (provider override → free namespace → canonical → glob pattern).
func WireCatalog(_ *db.Store) {
	db.DefaultProviderPricing = modelcatalog.DefaultProviderPricing()
	db.PricingResolver = func(provider, model string) db.Record {
		rec := modelcatalog.PricingFor(provider, model)
		if rec == nil {
			return nil
		}
		return db.Record(rec)
	}
}

func init() { WireCatalog(nil) }
