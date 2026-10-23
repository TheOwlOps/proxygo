package db

// Repo interfaces, named after the JS modules in src/lib/db/repos/.
// Records are dynamic maps (Record) exactly like the JS objects: column
// fields are materialised into the map and every other key is preserved
// in the JSON `data`/`value` column.

// --- filters (JS filter objects) ---

type ConnectionFilter struct {
	Provider string
	IsActive *bool
}

type NodeFilter struct {
	Type string
}

type ProxyPoolFilter struct {
	IsActive   *bool
	TestStatus string
}

type UsageFilter struct {
	Provider  string
	Model     string
	StartDate string // ISO or any time.Parse-able date; "" = unbounded
	EndDate   string
}

type RequestDetailsFilter struct {
	Provider     string
	Model        string
	ConnectionID string
	Status       string
	StartDate    string
	EndDate      string
	Page         int // 1-based; 0 = default 1
	PageSize     int // 0 = default 50
}

type RequestDetailsPage struct {
	Details    []Record `json:"details"`
	Pagination Record   `json:"pagination"` // {page,pageSize,totalItems,totalPages,hasNext,hasPrev}
}

// KeyAccess mirrors src/shared/utils/keyAccess.js access objects.
type KeyAccess struct {
	Restricted bool     `json:"restricted"`
	Allow      []string `json:"allow"`
}

// NameConflictError mirrors the typed error thrown by
// createProviderConnection when allowOverwrite === false and an apikey
// connection with the same name already exists (JS err.code =
// "PROVIDER_NAME_CONFLICT", with existingId/existingName attached).
type NameConflictError struct {
	ExistingID   string
	ExistingName string
	Provider     string
}

func (e *NameConflictError) Error() string {
	return "A connection named \"" + e.ExistingName + "\" already exists for provider \"" +
		e.Provider + "\". Pass allowOverwrite: true to replace it."
}

// Code mirrors err.code in JS.
func (e *NameConflictError) Code() string { return "PROVIDER_NAME_CONFLICT" }

// --- repo interfaces (one per JS repos/*.js file) ---

// SettingsRepo — settingsRepo.js. Settings are a single JSON document.
type SettingsRepo interface {
	GetSettings() (Record, error)
	UpdateSettings(updates Record) (Record, error)
	IsCloudEnabled() (bool, error)
	GetCloudURL() (string, error)
	ExportSettings() (Record, error)
}

// ConnectionsRepo — connectionsRepo.js (providerConnections table).
type ConnectionsRepo interface {
	GetProviderConnections(filter ConnectionFilter) ([]Record, error)
	GetProviderConnectionByID(id string) (Record, error)
	CreateProviderConnection(data Record) (Record, error)
	UpdateProviderConnection(id string, data Record) (Record, error)
	DeleteProviderConnection(id string) (bool, error)
	DeleteProviderConnectionsByProvider(providerID string) (int64, error)
	ReorderProviderConnections(providerID string) error
	CleanupProviderConnections() (int, error)
}

// NodesRepo — nodesRepo.js (providerNodes table).
type NodesRepo interface {
	GetProviderNodes(filter NodeFilter) ([]Record, error)
	GetProviderNodeByID(id string) (Record, error)
	CreateProviderNode(data Record) (Record, error)
	UpdateProviderNode(id string, data Record) (Record, error)
	DeleteProviderNode(id string) (Record, error)
}

// ProxyPoolsRepo — proxyPoolsRepo.js (proxyPools table).
type ProxyPoolsRepo interface {
	GetProxyPools(filter ProxyPoolFilter) ([]Record, error)
	GetProxyPoolByID(id string) (Record, error)
	CreateProxyPool(data Record) (Record, error)
	UpdateProxyPool(id string, data Record) (Record, error)
	DeleteProxyPool(id string) (Record, error)
}

// APIKeysRepo — apiKeysRepo.js (apiKeys table).
type APIKeysRepo interface {
	GetAPIKeys() ([]Record, error)
	GetAPIKeyByID(id string) (Record, error)
	GetAPIKeyByKey(key string) (Record, error)
	CreateAPIKey(name, machineID string) (Record, error)
	CreateAPIKeyWithKey(name, machineID, key string) (Record, error)
	UpdateAPIKey(id string, data Record) (Record, error)
	DeleteAPIKey(id string) (bool, error)
	ValidateAPIKey(key string) (bool, error)
}

// CombosRepo — combosRepo.js (combos table).
type CombosRepo interface {
	GetCombos() ([]Record, error)
	GetComboByID(id string) (Record, error)
	GetComboByName(name string) (Record, error)
	CreateCombo(data Record) (Record, error)
	UpdateCombo(id string, data Record) (Record, error)
	DeleteCombo(id string) (bool, error)
}

// AliasesRepo — aliasRepo.js (kv scopes modelAliases/customModels/mitmAlias).
type AliasesRepo interface {
	GetModelAliases() (Record, error)
	SetModelAlias(alias, model string) error
	DeleteModelAlias(alias string) error
	GetCustomModels() ([]Record, error)
	AddCustomModel(m Record) (bool, error)
	DeleteCustomModel(providerAlias, id, typ string) error
	GetMitmAlias(toolName string) (Record, error)
	SetMitmAliasAll(toolName string, mappings Record) error
}

// PricingRepo — pricingRepo.js (kv scope "pricing": user overrides merged
// over the built-in PROVIDER_PRICING, which belongs to the providers
// package; see DefaultProviderPricing / PricingResolver hooks).
type PricingRepo interface {
	GetPricing() (Record, error)
	GetPricingForModel(provider, model string) (Record, error)
	UpdatePricing(pricingData Record) (Record, error)
	ResetPricing(provider, model string) (Record, error)
	ResetAllPricing() (Record, error)
}

// DisabledModelsRepo — disabledModelsRepo.js (kv scope "disabledModels").
type DisabledModelsRepo interface {
	GetDisabledModels() (Record, error)
	GetDisabledByProvider(providerAlias string) ([]any, error)
	DisableModels(providerAlias string, ids []any) error
	EnableModels(providerAlias string, ids []any) error
}

// UsageRepo — usageRepo.js (usageHistory + usageDaily + _meta counter).
// GetUsageStats/GetChartData return JS-shaped structures as Records /
// slices; pending-request tracking is in-memory like the JS globals.
type UsageRepo interface {
	TrackPendingRequest(model, provider, connectionID string, started, isErr bool)
	GetActiveRequests() (Record, error)
	SaveRequestUsage(entry Record) error
	GetUsageHistory(filter UsageFilter) ([]Record, error)
	GetUsageStats(period string) (Record, error)
	GetChartData(period string) ([]Record, error)
	AppendRequestLog() error // no-op in JS (logs derive from usageHistory)
	GetRecentLogs(limit int) ([]string, error)
}

// RequestDetailsRepo — requestDetailsRepo.js (requestDetails table).
// Divergence: JS buffers writes and flushes async; Go writes
// synchronously on Save (same resulting rows). See README.md.
type RequestDetailsRepo interface {
	SaveRequestDetail(detail Record) error
	GetRequestDetails(filter RequestDetailsFilter) (*RequestDetailsPage, error)
	GetDistinctProviders() ([]string, error)
	GetRequestDetailByID(id string) (Record, error)
}

// KVStore — helpers/kvStore.js (makeKv) + helpers/metaStore.js.
type KVStore interface {
	Scoped(scope string) KVScope
	GetMeta(key string, fallback string) (string, error)
	SetMeta(key, value string) error
}

// KVScope is one makeKv(scope) instance.
type KVScope interface {
	Get(key string, fallback any) (any, error)
	GetAll() (Record, error)
	Set(key string, value any) error
	SetMany(obj Record) error
	Remove(key string) error
	Clear() error
}
