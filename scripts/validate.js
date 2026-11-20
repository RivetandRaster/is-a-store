#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');
const { validateDomainPayload, isMaintainer } = require('./lib/dns-rules');

const ROOT_DIR = path.resolve(__dirname, '..');
const CONFIG_PATH = path.join(ROOT_DIR, 'config', 'registry.config.json');
const DOMAINS_DIR = path.join(ROOT_DIR, 'registry', 'domains');

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
}

function appendSummary(markdown) {
  const summaryPath = process.env.GITHUB_STEP_SUMMARY;
  if (summaryPath) {
    fs.appendFileSync(summaryPath, markdown + '\n', 'utf8');
  }
}

function main() {
  const config = loadConfig();
  if (!fs.existsSync(DOMAINS_DIR)) {
    console.error('ERROR: registry/domains directory does not exist.');
    process.exit(1);
  }

  const entries = fs.readdirSync(DOMAINS_DIR, { withFileTypes: true });
  const ownerCounts = new Map();
  const failures = [];
  let validCount = 0;

  for (const entry of entries) {
    const relPath = `registry/domains/${entry.name}`;
    if (entry.name.startsWith('.')) continue;

    if (!entry.isFile()) {
      failures.push({ file: relPath, errors: ['Subdirectories are not permitted in registry/domains/.'] });
      continue;
    }

    if (!entry.name.endsWith('.json')) {
      failures.push({ file: relPath, errors: ['Only .json files are permitted in registry/domains/.'] });
      continue;
    }

    const subdomain = entry.name.slice(0, -'.json'.length);
    const fullPath = path.join(DOMAINS_DIR, entry.name);

    let data;
    try {
      const raw = fs.readFileSync(fullPath, 'utf8');
      data = JSON.parse(raw);
    } catch (err) {
      failures.push({ file: relPath, errors: [`Invalid JSON syntax: ${err.message}`] });
      continue;
    }

    const { errors } = validateDomainPayload(subdomain, data, config);

    if (errors.length > 0) {
      failures.push({ file: relPath, errors });
    } else {
      validCount += 1;
      const ownerKey = data.owner.github.toLowerCase();
      if (!isMaintainer(ownerKey, config) && (data.status ?? 'active') === 'active') {
        const list = ownerCounts.get(ownerKey) || [];
        list.push(subdomain);
        ownerCounts.set(ownerKey, list);
      }
    }
  }

  // Enforce per-owner subdomain quota (zero-cost anti-squatting rate limit)
  const maxPerOwner = config.limits?.maxDomainsPerOwner ?? 3;
  for (const [owner, subdomains] of ownerCounts.entries()) {
    if (subdomains.length > maxPerOwner) {
      failures.push({
        file: `registry/domains/${subdomains[subdomains.length - 1]}.json`,
        errors: [
          `Owner "${owner}" has ${subdomains.length} active subdomains (${subdomains.join(', ')}), exceeding the limit of ${maxPerOwner} per user.`
        ]
      });
    }
  }

  if (failures.length > 0) {
    console.error(`\nValidation FAILED with ${failures.length} invalid file(s):\n`);
    const summaryLines = ['### Subdomain Validation Failed', ''];
    for (const item of failures) {
      console.error(`File: ${item.file}`);
      summaryLines.push(`- **\`${item.file}\`**`);
      for (const err of item.errors) {
        console.error(`  - ${err}`);
        console.log(`::error file=${item.file}::${err}`);
        summaryLines.push(`  - ${err}`);
      }
    }
    appendSummary(summaryLines.join('\n'));
    process.exit(1);
  }

  const msg = `Validation PASSED: ${validCount} subdomain record(s) verified against schema, DNS rules, and security policies.`;
  console.log(msg);
  appendSummary(`### Subdomain Validation Passed\n\n- Verified **${validCount}** subdomain file(s) with zero errors.`);
}

main();
