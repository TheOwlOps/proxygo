package db

import (
	"database/sql"
	"sync"
	"time"
)

// Port of repos/pricingRepo.js (kv scope "pricing").
//
// In JS, getPricing() merges user overrides over PROVIDER_PRICING from
// open-sse/providers/pricing.js. That catalogue belongs to the providers
// package in the Go port, so it is injected through hooks:
//
//   - DefaultProviderPricing: the built-in PROVIDER_PRICING map
//     (provider -> model -> pricing record).
//   - PricingResolver: equivalent of open-sse getPricingForModel()
//     (provider override → free namespaces → canonical → patterns).
//     Used by GetPricingForModel (after user overrides) and by the usage
//     repo's cost calculation.
//
// When the hooks are unset, user pricing alone is returned/resolved —
// the parent (integration) wires the real catalogue at startup.

var (
	DefaultProviderPricing map[string]any
	PricingResolver        func(provider, model string) Record
)

const pricingScope = "pricing"
const pricingCacheTTL = 5 * time.Second

var pricingCache struct {
	mu        sync.Mutex
	value     Record
	expiresAt time.Time
}

func invalidatePricingCache() {
	pricingCache.mu.Lock()
	pricingCache.value = nil
	pricingCache.expiresAt = time.Time{}
	pricingCache.mu.Unlock()
}

func (s *Store) pricingKV() KVScope { return &kvStore{s: s, scope: pricingScope} }

func (s *Store) getUserPricing() (Record, error) {
	return s.pricingKV().GetAll()
}

// GetPricing returns built-in pricing merged with user overrides
// (user wins per model, shallow-merged per pricing record), with the
// same 5s cache as the JS repo.
func (s *Store) GetPricing() (Record, error) {
	pricingCache.mu.Lock()
	if pricingCache.value != nil && time.Now().Before(pricingCache.expiresAt) {
		v := pricingCache.value
		pricingCache.mu.Unlock()
		return v, nil
	}
	pricingCache.mu.Unlock()

	userPricing, err := s.getUserPricing()
	if err != nil {
		return nil, err
	}
	merged := Record{}
	for provider, models := range DefaultProviderPricing {
		merged[provider] = cloneMap(toMap(models))
	}
	for provider, modelsAny := range userPricing {
		models := toMap(modelsAny)
		dst, ok := merged[provider].(map[string]any)
		if !ok {
			dst = Record{}
			merged[provider] = dst
		}
		for model, pricing := range models {
			if existing, ok := dst[model]; ok {
				dst[model] = mergeMaps(toMap(existing), toMap(pricing))
			} else {
				dst[model] = pricing
			}
		}
	}

	pricingCache.mu.Lock()
	pricingCache.value = merged
	pricingCache.expiresAt = time.Now().Add(pricingCacheTTL)
	pricingCache.mu.Unlock()
	return merged, nil
}

// GetPricingForModel: user override first, else the injected resolver
// (JS delegates to open-sse getPricingForModel).
func (s *Store) GetPricingForModel(provider, model string) (Record, error) {
	if model == "" {
		return nil, nil
	}
	userPricing, err := s.getUserPricing()
	if err != nil {
		return nil, err
	}
	if provider != "" {
		if models, ok := userPricing[provider]; ok {
			if p, ok := toMap(models)[model]; ok {
				return toMap(p), nil
			}
		}
	}
	if PricingResolver != nil {
		return PricingResolver(provider, model), nil
	}
	// Fallback when no resolver is wired: built-in provider pricing only.
	if provider != "" {
		if models, ok := DefaultProviderPricing[provider]; ok {
			if p, ok := toMap(models)[model]; ok {
				return toMap(p), nil
			}
		}
	}
	return nil, nil
}

// UpdatePricing merges pricingData over the stored user pricing per
// provider (atomic read-merge-write), and returns the user pricing.
func (s *Store) UpdatePricing(pricingData Record) (Record, error) {
	err := s.tx(func(tx *sql.Tx) error {
		for provider, modelsAny := range pricingData {
			models := toMap(modelsAny)
			raw, found, err := kvGetQ(tx, pricingScope, provider)
			if err != nil {
				return err
			}
			current := Record{}
			if found {
				current = parseMap(raw)
			}
			for model, pricing := range models {
				current[model] = pricing
			}
			if err := kvSetQ(tx, pricingScope, provider, current); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	invalidatePricingCache()
	return s.getUserPricing()
}

// ResetPricing removes one model (or the whole provider when model=="").
func (s *Store) ResetPricing(provider, model string) (Record, error) {
	if provider == "" {
		return s.getUserPricing()
	}
	err := s.tx(func(tx *sql.Tx) error {
		if model == "" {
			_, err := tx.Exec(`DELETE FROM kv WHERE scope = 'pricing' AND key = ?`, provider)
			return err
		}
		raw, found, err := kvGetQ(tx, pricingScope, provider)
		if err != nil {
			return err
		}
		current := Record{}
		if found {
			current = parseMap(raw)
		}
		delete(current, model)
		if len(current) == 0 {
			_, err := tx.Exec(`DELETE FROM kv WHERE scope = 'pricing' AND key = ?`, provider)
			return err
		}
		return kvSetQ(tx, pricingScope, provider, current)
	})
	if err != nil {
		return nil, err
	}
	invalidatePricingCache()
	return s.getUserPricing()
}

func (s *Store) ResetAllPricing() (Record, error) {
	if err := s.pricingKV().Clear(); err != nil {
		return nil, err
	}
	invalidatePricingCache()
	return Record{}, nil
}

// CalculateCostFromTokens ports open-sse/providers/pricing.js
// calculateCostFromTokens (prices are USD per 1M tokens; prompt_tokens is
// cache-inclusive, so cached/cache-creation tokens are subtracted from
// the full-rate input first).
func CalculateCostFromTokens(tokens, pricing Record) float64 {
	if tokens == nil || pricing == nil {
		return 0
	}
	inputTokens := tokNum(tokens, "prompt_tokens", "input_tokens")
	cachedTokens := tokNum(tokens, "cached_tokens", "cache_read_input_tokens")
	cacheCreationTokens := numVal(tokens["cache_creation_input_tokens"])
	nonCachedInput := inputTokens - cachedTokens - cacheCreationTokens
	if nonCachedInput < 0 {
		nonCachedInput = 0
	}
	cost := nonCachedInput * (numVal(pricing["input"]) / 1e6)
	if cachedTokens > 0 {
		rate := numVal(pricing["cached"])
		if pricing["cached"] == nil {
			rate = numVal(pricing["input"])
		}
		cost += cachedTokens * (rate / 1e6)
	}
	outputTokens := tokNum(tokens, "completion_tokens", "output_tokens")
	cost += outputTokens * (numVal(pricing["output"]) / 1e6)
	reasoningTokens := numVal(tokens["reasoning_tokens"])
	if reasoningTokens > 0 {
		rate := numVal(pricing["reasoning"])
		if pricing["reasoning"] == nil {
			rate = numVal(pricing["output"])
		}
		cost += reasoningTokens * (rate / 1e6)
	}
	if cacheCreationTokens > 0 {
		rate := numVal(pricing["cache_creation"])
		if pricing["cache_creation"] == nil {
			rate = numVal(pricing["input"])
		}
		cost += cacheCreationTokens * (rate / 1e6)
	}
	return cost
}

func tokNum(tokens Record, keys ...string) float64 {
	for _, k := range keys {
		if v, ok := tokens[k]; ok && v != nil {
			return numVal(v)
		}
	}
	return 0
}
