#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const DOMAINS_DIR = path.join(ROOT_DIR, 'registry', 'domains');

function main() {
  if (!fs.existsSync(DOMAINS_DIR)) {
    console.error('ERROR: registry/domains directory not found.');
    process.exit(1);
  }

  const files = fs
    .readdirSync(DOMAINS_DIR)
    .filter((f) => !f.startsWith('.') && f.endsWith('.json'));

  const seenNormalized = new Map();
  const seenCnameTargets = new Map();
  const errors = [];

  for (const file of files) {
    const rawName = file.slice(0, -'.json'.length);
    const normalized = rawName.toLowerCase();

    if (seenNormalized.has(normalized)) {
      errors.push(
        `Duplicate subdomain collision: "${file}" conflicts with "${seenNormalized.get(normalized)}".`
      );
    } else {
      seenNormalized.set(normalized, file);
    }

    // Track duplicate CNAME targets across different owners (informational warning)
    try {
      const data = JSON.parse(fs.readFileSync(path.join(DOMAINS_DIR, file), 'utf8'));
      if (data?.record?.CNAME) {
        const target = String(data.record.CNAME).toLowerCase();
        const list = seenCnameTargets.get(target) || [];
        list.push({ subdomain: normalized, owner: data?.owner?.github || 'unknown' });
        seenCnameTargets.set(target, list);
      }
    } catch {
      // JSON syntax errors are reported by validate.js
    }
  }

  if (errors.length > 0) {
    console.error('Duplicate check FAILED:');
    for (const err of errors) {
      console.error(`  - ${err}`);
      console.log(`::error::${err}`);
    }
    process.exit(1);
  }

  for (const [target, owners] of seenCnameTargets.entries()) {
    const distinctOwners = new Set(owners.map((o) => o.owner.toLowerCase()));
    if (distinctOwners.size > 1) {
      console.log(
        `::warning::CNAME target "${target}" is referenced by multiple distinct owners: ${owners
          .map((o) => `${o.subdomain} (${o.owner})`)
          .join(', ')}`
      );
    }
  }

  console.log(`Duplicate check PASSED: ${files.length} unique subdomain(s) verified.`);
}

main();
