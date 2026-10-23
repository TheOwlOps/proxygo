#!/usr/bin/env node
// extract_provider_models.mjs — Team K, 9Router → Go port (Phase 2).
//
// Extracts the model catalogue + pricing data the JS runtime uses:
//
//   1. PROVIDER_MODELS — built by ~/workspace/9router/open-sse/providers/index.js
//      from providers/registry/*.js (+ config/ttsModels.js) and re-exported by
//      open-sse/config/providerModels.js. Keyed by provider alias (or id);
//      each entry is one model object whose fields carry the per-model
//      metadata chatCore consults: targetFormat, supportedFormats,
//      upstreamModelId, kind/type, quotaFamily, strip, thinking hints, …
//      Entries are dumped verbatim (unknown fields preserved).
//
//   2. Pricing — open-sse/providers/pricing.js:
//      PROVIDER_PRICING (per-provider overrides), MODEL_PRICING (canonical
//      per-model rates), PATTERN_PRICING (glob fallbacks, order matters),
//      FREE_MODEL_NAMESPACES, ZERO_PRICING. This is the data behind
//      getPricingForModel() and db pricingRepo's PROVIDER_PRICING merge.
//
// Output: ~/workspace/9router-go/internal/modelcatalog/catalog.json
// The generated file is NEVER hand-edited — re-run this script instead.
// Per-key extraction failures are recorded under "failures" and printed,
// never silently dropped (same convention as extract_registry.mjs).
//
// Usage:
//   node tools/extract_provider_models.mjs [--src <9routerRoot>] [--out <jsonFile>]
// Defaults resolve relative to this script:
//   src = ../../9router
//   out = ../internal/modelcatalog/catalog.json

import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));

function argValue(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? resolve(process.argv[i + 1]) : fallback;
}

const srcRoot = argValue("--src", resolve(scriptDir, "../../9router"));
const outFile = argValue("--out", resolve(scriptDir, "../internal/modelcatalog/catalog.json"));

// Deep-scan for values JSON cannot represent. Returns a description of the
// first offender or null. (Same helper as extract_registry.mjs.)
function findNonSerializable(value, path, seen) {
  const t = typeof value;
  if (t === "function" || t === "symbol" || t === "bigint" || t === "undefined") {
    return `${path}: ${t} is not JSON-serializable`;
  }
  if (value !== null && t === "object") {
    if (seen.has(value)) return `${path}: circular reference`;
    seen.add(value);
    const entries = Array.isArray(value)
      ? value.map((v, i) => [String(i), v])
      : Object.entries(value);
    for (const [k, v] of entries) {
      const hit = findNonSerializable(v, `${path}.${k}`, seen);
      if (hit) return hit;
    }
    seen.delete(value);
  }
  return null;
}

const failures = [];

// --- 1. PROVIDER_MODELS -----------------------------------------------------
const providerModels = {};
let modelTotal = 0;
let targetFormatTotal = 0;
try {
  const mod = await import(
    pathToFileURL(resolve(srcRoot, "open-sse/config/providerModels.js")).href
  );
  const pm = mod.PROVIDER_MODELS;
  if (pm === null || typeof pm !== "object" || Array.isArray(pm)) {
    failures.push({ key: "PROVIDER_MODELS", error: "export is not an object" });
  } else {
    for (const [key, models] of Object.entries(pm)) {
      if (!Array.isArray(models)) {
        failures.push({ key, error: "PROVIDER_MODELS entry is not an array" });
        continue;
      }
      const bad = findNonSerializable(models, `$[${JSON.stringify(key)}]`, new Set());
      if (bad) {
        failures.push({ key, error: bad });
        continue;
      }
      const clean = JSON.parse(JSON.stringify(models));
      providerModels[key] = clean;
      modelTotal += clean.length;
      targetFormatTotal += clean.filter(
        (m) => m && typeof m === "object" && m.targetFormat
      ).length;
    }
  }
} catch (err) {
  failures.push({ key: "PROVIDER_MODELS", error: String((err && err.message) || err) });
}

// --- 2. Pricing -------------------------------------------------------------
const pricing = {};
try {
  const mod = await import(
    pathToFileURL(resolve(srcRoot, "open-sse/providers/pricing.js")).href
  );
  for (const name of [
    "PROVIDER_PRICING",
    "MODEL_PRICING",
    "PATTERN_PRICING",
    "FREE_MODEL_NAMESPACES",
    "ZERO_PRICING",
  ]) {
    const v = mod[name];
    if (v === undefined) {
      failures.push({ key: `pricing.${name}`, error: "export missing" });
      continue;
    }
    const bad = findNonSerializable(v, `$.${name}`, new Set());
    if (bad) {
      failures.push({ key: `pricing.${name}`, error: bad });
      continue;
    }
    pricing[
      name.charAt(0).toLowerCase() + name.slice(1).replace(/_([A-Z])/g, (_, c) => c.toUpperCase()).replace(/_/g, "")
    ] = JSON.parse(JSON.stringify(v));
  }
  // Normalise keys explicitly (avoid clever-casing surprises):
  pricing.providerPricing = JSON.parse(JSON.stringify(mod.PROVIDER_PRICING ?? null));
  pricing.modelPricing = JSON.parse(JSON.stringify(mod.MODEL_PRICING ?? null));
  pricing.patternPricing = JSON.parse(JSON.stringify(mod.PATTERN_PRICING ?? []));
  pricing.freeModelNamespaces = JSON.parse(JSON.stringify(mod.FREE_MODEL_NAMESPACES ?? []));
  pricing.zeroPricing = JSON.parse(JSON.stringify(mod.ZERO_PRICING ?? null));
  for (const k of Object.keys(pricing)) {
    if (!["providerPricing", "modelPricing", "patternPricing", "freeModelNamespaces", "zeroPricing"].includes(k)) {
      delete pricing[k];
    }
  }
} catch (err) {
  failures.push({ key: "pricing", error: String((err && err.message) || err) });
}

const providerKeys = Object.keys(providerModels).length;
const pricedModels = pricing.modelPricing ? Object.keys(pricing.modelPricing).length : 0;
const providerPricedModels = pricing.providerPricing
  ? Object.values(pricing.providerPricing).reduce((n, m) => n + Object.keys(m).length, 0)
  : 0;

const out = {
  source:
    "open-sse/config/providerModels.js (PROVIDER_MODELS) + open-sse/providers/pricing.js (9router v0.5.104 @ 87a74e1)",
  generatedBy: "tools/extract_provider_models.mjs — do not hand-edit",
  counts: {
    providerKeys,
    models: modelTotal,
    modelsWithTargetFormat: targetFormatTotal,
    pricedModels,
    providerPricedModels,
    patterns: Array.isArray(pricing.patternPricing) ? pricing.patternPricing.length : 0,
  },
  providerModels,
  pricing,
  failures,
};

mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify(out, null, 2) + "\n");

console.log(`provider keys: ${providerKeys}, models: ${modelTotal} (${targetFormatTotal} with targetFormat)`);
console.log(`priced models: ${pricedModels} canonical + ${providerPricedModels} provider overrides, patterns: ${out.counts.patterns}`);
console.log(`wrote ${outFile}`);
for (const f of failures) console.error(`FAILED ${f.key}: ${f.error}`);
if (failures.length > 0) {
  console.error(`${failures.length} extraction failure(s) — see "failures" in ${outFile}`);
  process.exitCode = 1;
}
