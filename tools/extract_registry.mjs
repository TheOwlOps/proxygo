#!/usr/bin/env node
// extract_registry.mjs — Team B, ProxyGo → Go port.
//
// Reads every provider registry file from the JS source repo
//   ~/workspace/9router/open-sse/providers/registry/*.js
// (each is `export default { … }`, some importing shared constants),
// dynamic-imports it, and dumps the default export verbatim to JSON:
//
//   ~/workspace/9router-go/internal/providers/registry.json
//
// The generated file is NEVER hand-edited — re-run this script instead.
// Per-file extraction failures are recorded in the output JSON under
// "failures" (file + error) and printed to stderr, never silently dropped.
// Files whose default export is not a provider object (index.js, the
// auto-generated aggregator) are recorded under "skipped" with the reason.
//
// Usage:
//   node tools/extract_registry.mjs [--src <registryDir>] [--out <jsonFile>]
// Defaults resolve relative to this script:
//   src = ../../9router/open-sse/providers/registry
//   out = ../internal/providers/registry.json

import { readdirSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const scriptDir = dirname(fileURLToPath(import.meta.url));

function argValue(flag, fallback) {
  const i = process.argv.indexOf(flag);
  return i >= 0 && process.argv[i + 1] ? resolve(process.argv[i + 1]) : fallback;
}

const srcDir = argValue("--src", resolve(scriptDir, "../../9router/open-sse/providers/registry"));
const outFile = argValue("--out", resolve(scriptDir, "../internal/providers/registry.json"));

// Deep-scan for values JSON cannot represent (function/symbol/bigint/
// undefined/circular). Returns a description of the first offender or null.
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

const files = readdirSync(srcDir).filter((f) => f.endsWith(".js")).sort();
const providers = [];
const failures = [];
const skipped = [];

for (const file of files) {
  let def;
  try {
    const mod = await import(pathToFileURL(resolve(srcDir, file)).href);
    def = mod.default;
  } catch (err) {
    failures.push({ file, error: String((err && err.message) || err) });
    continue;
  }
  if (def === null || typeof def !== "object" || Array.isArray(def)) {
    const kind = Array.isArray(def) ? "array" : def === null ? "null" : typeof def;
    skipped.push({
      file,
      error: `default export is ${kind}, not a provider object (aggregator/index file)`,
    });
    continue;
  }
  if (typeof def.id !== "string" || def.id === "") {
    failures.push({ file, error: "default export has no string `id`" });
    continue;
  }
  const bad = findNonSerializable(def, "$", new Set());
  if (bad) {
    failures.push({ file, error: bad });
    continue;
  }
  // Round-trip through JSON so the embedded data is exactly what Go sees.
  providers.push(JSON.parse(JSON.stringify(def)));
}

const out = {
  source: "open-sse/providers/registry/*.js (9router v0.5.104 @ 87a74e1)",
  generatedBy: "tools/extract_registry.mjs — do not hand-edit",
  providers,
  failures,
  skipped,
};

mkdirSync(dirname(outFile), { recursive: true });
writeFileSync(outFile, JSON.stringify(out, null, 2) + "\n");

console.log(`scanned ${files.length} files in ${srcDir}`);
console.log(`extracted ${providers.length} providers -> ${outFile}`);
for (const s of skipped) console.log(`SKIPPED ${s.file}: ${s.error}`);
for (const f of failures) console.error(`FAILED ${f.file}: ${f.error}`);
if (failures.length > 0) {
  console.error(`${failures.length} extraction failure(s) — see "failures" in ${outFile}`);
  process.exitCode = 1;
}
