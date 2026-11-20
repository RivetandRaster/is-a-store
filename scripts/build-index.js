#!/usr/bin/env node
'use strict';

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');
const CONFIG_PATH = path.join(ROOT_DIR, 'config', 'registry.config.json');
const DOMAINS_DIR = path.join(ROOT_DIR, 'registry', 'domains');
const INDEX_OUT = path.join(ROOT_DIR, 'registry', 'index.json');
const STATS_OUT = path.join(ROOT_DIR, 'registry', 'stats.json');

function summarizeDestination(record) {
  if (record.CNAME) return record.CNAME;
  if (record.A) return record.A.join(', ');
  if (record.AAAA) return record.AAAA.join(', ');
  if (record.MX) return record.MX.map((m) => `${m.priority} ${m.target}`).join(', ');
  if (record.TXT) return record.TXT[0];
  return '';
}

function main() {
  const config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  const files = fs
    .readdirSync(DOMAINS_DIR)
    .filter((f) => !f.startsWith('.') && f.endsWith('.json'))
    .sort((a, b) => a.localeCompare(b));

  const recordTypeCounts = { CNAME: 0, A: 0, AAAA: 0, TXT: 0, MX: 0 };
  const uniqueOwners = new Set();
  const domains = [];

  for (const file of files) {
    const subdomain = file.slice(0, -'.json'.length).toLowerCase();
    const data = JSON.parse(fs.readFileSync(path.join(DOMAINS_DIR, file), 'utf8'));
    const types = Object.keys(data.record || {});
    const status = data.status || 'active';

    for (const t of types) {
      if (recordTypeCounts[t] !== undefined) {
        recordTypeCounts[t] += 1;
      }
    }
    if (data.owner?.github) {
      uniqueOwners.add(data.owner.github.toLowerCase());
    }

    domains.push({
      subdomain,
      fqdn: `${subdomain}.${config.rootDomain}`,
      description: data.description,
      repo: data.repo || null,
      owner: data.owner.github,
      recordTypes: types,
      record: data.record,
      destination: summarizeDestination(data.record),
      proxied: Boolean(data.proxied),
      status: status === 'suspended' ? 'suspended' : config.dnsLiveMode ? 'active' : 'indexed',
      suspensionReason: data.suspensionReason || null
    });
  }

  const generatedAt = new Date().toISOString();
  const stats = {
    generatedAt,
    rootDomain: config.rootDomain,
    dnsLiveMode: Boolean(config.dnsLiveMode),
    totalRegistered: domains.length,
    activeCount: domains.filter((d) => d.status !== 'suspended').length,
    suspendedCount: domains.filter((d) => d.status === 'suspended').length,
    uniqueOwners: uniqueOwners.size,
    recordTypes: recordTypeCounts
  };

  const indexPayload = {
    generatedAt,
    rootDomain: config.rootDomain,
    dnsLiveMode: Boolean(config.dnsLiveMode),
    total: domains.length,
    domains
  };

  fs.writeFileSync(INDEX_OUT, JSON.stringify(indexPayload, null, 2) + '\n', 'utf8');
  fs.writeFileSync(STATS_OUT, JSON.stringify(stats, null, 2) + '\n', 'utf8');

  console.log(`Built registry/index.json and registry/stats.json (${domains.length} domain(s)).`);
}

main();
