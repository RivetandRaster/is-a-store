#!/usr/bin/env node
'use strict';

/**
 * Idempotent Cloudflare DNS API v4 reconciler for is-a.store.
 *
 * Safety guarantees:
 * 1. Only runs on trusted main-branch deploys (never on untrusted PRs).
 * 2. Safe no-op when dnsSyncEnabled is false or CF_API_TOKEN/CF_ZONE_ID are unset.
 * 3. Only modifies/deletes Cloudflare records carrying comment "managed-by:is-a-store"
 *    so apex records, GitHub Pages verification records, and manual zone records are untouched.
 * 4. Suspended domains are removed from Cloudflare DNS while remaining reserved in Git.
 */

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const CONFIG_PATH = path.join(ROOT_DIR, 'config', 'registry.config.json');
const DOMAINS_DIR = path.join(ROOT_DIR, 'registry', 'domains');
const MANAGED_COMMENT = 'managed-by:is-a-store';

async function cfRequest(zoneId, token, endpoint, options = {}) {
  const res = await fetch(
    `https://api.cloudflare.com/client/v4/zones/${zoneId}${endpoint}`,
    {
      ...options,
      headers: {
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
        ...(options.headers || {})
      }
    }
  );
  const json = await res.json();
  if (!res.ok || !json.success) {
    throw new Error(
      `Cloudflare API error (${res.status}) on ${endpoint}: ${JSON.stringify(json.errors)}`
    );
  }
  return json;
}

async function listManagedRecords(zoneId, token) {
  const records = [];
  let page = 1;
  while (true) {
    const res = await cfRequest(
      zoneId,
      token,
      `/dns_records?per_page=100&page=${page}&comment.exact=${encodeURIComponent(MANAGED_COMMENT)}`
    );
    records.push(...res.result);
    if (!res.result_info || page >= res.result_info.total_pages) break;
    page += 1;
  }
  return records;
}

function buildDesiredRecords(config) {
  const desired = [];
  const ttl = config.limits?.defaultTtl ?? 3600;
  const files = fs
    .readdirSync(DOMAINS_DIR)
    .filter((f) => !f.startsWith('.') && f.endsWith('.json'));

  for (const file of files) {
    const subdomain = file.slice(0, -'.json'.length).toLowerCase();
    const data = JSON.parse(fs.readFileSync(path.join(DOMAINS_DIR, file), 'utf8'));
    if ((data.status || 'active') === 'suspended') {
      continue; // Suspended entries are intentionally excluded from live DNS
    }

    const fqdn = `${subdomain}.${config.rootDomain}`.toLowerCase();
    const proxied = Boolean(data.proxied);
    const rec = data.record || {};

    if (rec.CNAME) {
      desired.push({
        type: 'CNAME',
        name: fqdn,
        content: rec.CNAME.toLowerCase(),
        ttl: proxied ? 1 : ttl,
        proxied,
        comment: MANAGED_COMMENT
      });
    }
    if (Array.isArray(rec.A)) {
      for (const ip of rec.A) {
        desired.push({
          type: 'A',
          name: fqdn,
          content: ip,
          ttl: proxied ? 1 : ttl,
          proxied,
          comment: MANAGED_COMMENT
        });
      }
    }
    if (Array.isArray(rec.AAAA)) {
      for (const ip of rec.AAAA) {
        desired.push({
          type: 'AAAA',
          name: fqdn,
          content: ip,
          ttl: proxied ? 1 : ttl,
          proxied,
          comment: MANAGED_COMMENT
        });
      }
    }
    if (Array.isArray(rec.TXT)) {
      for (const txt of rec.TXT) {
        desired.push({
          type: 'TXT',
          name: fqdn,
          content: txt,
          ttl,
          proxied: false,
          comment: MANAGED_COMMENT
        });
      }
    }
    if (Array.isArray(rec.MX)) {
      for (const mx of rec.MX) {
        desired.push({
          type: 'MX',
          name: fqdn,
          content: mx.target.toLowerCase(),
          priority: mx.priority,
          ttl,
          proxied: false,
          comment: MANAGED_COMMENT
        });
      }
    }
  }

  return desired;
}

function recordKey(r) {
  return [
    r.type,
    String(r.name).toLowerCase(),
    String(r.content).toLowerCase(),
    r.priority ?? ''
  ].join('|');
}

async function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const token = process.env.CF_API_TOKEN;
  const zoneId = process.env.CF_ZONE_ID;

  if (!config.dnsSyncEnabled) {
    console.log('DNS sync skipped: config/registry.config.json has dnsSyncEnabled = false.');
    return;
  }

  if (!token || !zoneId) {
    console.log('DNS sync skipped: CF_API_TOKEN or CF_ZONE_ID secret is not configured.');
    return;
  }

  console.log(`Syncing DNS records for zone ${config.rootDomain}...`);
  const existing = await listManagedRecords(zoneId, token);
  const desired = buildDesiredRecords(config);

  const existingMap = new Map(existing.map((r) => [recordKey(r), r]));
  const desiredMap = new Map(desired.map((r) => [recordKey(r), r]));

  let created = 0;
  let updated = 0;
  let deleted = 0;

  for (const [key, want] of desiredMap.entries()) {
    const have = existingMap.get(key);
    if (!have) {
      await cfRequest(zoneId, token, '/dns_records', {
        method: 'POST',
        body: JSON.stringify(want)
      });
      created += 1;
    } else if (Boolean(have.proxied) !== Boolean(want.proxied)) {
      await cfRequest(zoneId, token, `/dns_records/${have.id}`, {
        method: 'PUT',
        body: JSON.stringify(want)
      });
      updated += 1;
    }
  }

  for (const [key, have] of existingMap.entries()) {
    if (!desiredMap.has(key)) {
      await cfRequest(zoneId, token, `/dns_records/${have.id}`, {
        method: 'DELETE'
      });
      deleted += 1;
    }
  }

  console.log(`DNS sync complete: ${created} created, ${updated} updated, ${deleted} deleted.`);
}

main().catch((err) => {
  console.error('DNS sync FAILED:', err.message);
  process.exit(1);
});
