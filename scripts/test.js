#!/usr/bin/env node
'use strict';

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { validateDomainPayload } = require('./lib/dns-rules');

const config = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'config', 'registry.config.json'), 'utf8')
);

let passed = 0;
function test(name, fn) {
  try {
    fn();
    passed += 1;
    console.log(`PASS: ${name}`);
  } catch (err) {
    console.error(`FAIL: ${name}`);
    console.error(`  ${err.message}`);
    process.exitCode = 1;
  }
}

test('Accepts valid CNAME pointing to owner GitHub Pages', () => {
  const { errors } = validateDomainPayload(
    'alice-shop',
    {
      description: 'Personal portfolio and digital store front',
      owner: { github: 'alice' },
      record: { CNAME: 'alice.github.io' },
      proxied: false
    },
    config
  );
  assert.deepStrictEqual(errors, []);
});

test('Accepts valid A + AAAA + TXT + MX combination', () => {
  const { errors } = validateDomainPayload(
    'builder',
    {
      description: 'Indie developer project with custom mail and verification',
      owner: { github: 'builderdev' },
      record: {
        A: ['93.184.216.34'],
        AAAA: ['2606:2800:220:1:248:1893:25c8:1946'],
        TXT: ['v=spf1 include:_spf.example.com ~all'],
        MX: [{ target: 'mx1.example.com', priority: 10 }]
      }
    },
    config
  );
  assert.deepStrictEqual(errors, []);
});

test('Rejects CNAME combined with TXT (RFC 1034 violation)', () => {
  const { errors } = validateDomainPayload(
    'conflict-test',
    {
      description: 'Attempting illegal CNAME plus TXT record',
      owner: { github: 'tester' },
      record: {
        CNAME: 'tester.github.io',
        TXT: ['hello=world']
      }
    },
    config
  );
  assert.ok(errors.some((e) => e.includes('CNAME cannot coexist')));
});

test('Rejects private IPv4 addresses (RFC 1918 / loopback / metadata)', () => {
  for (const ip of ['127.0.0.1', '10.0.0.5', '192.168.1.1', '172.16.0.1', '169.254.169.254']) {
    const { errors } = validateDomainPayload(
      'priv-test',
      {
        description: 'Testing private IPv4 blocking',
        owner: { github: 'tester' },
        record: { A: [ip] }
      },
      config
    );
    assert.ok(errors.length > 0, `Expected ${ip} to be rejected`);
  }
});

test('Rejects private IPv6 addresses (loopback / ULA / link-local)', () => {
  for (const ip of ['::1', 'fc00::1', 'fe80::1', '2001:db8::1']) {
    const { errors } = validateDomainPayload(
      'priv6-test',
      {
        description: 'Testing private IPv6 blocking',
        owner: { github: 'tester' },
        record: { AAAA: [ip] }
      },
      config
    );
    assert.ok(errors.length > 0, `Expected ${ip} to be rejected`);
  }
});

test('Rejects wildcard subdomains and reserved names for regular users', () => {
  const wildcard = validateDomainPayload(
    '*',
    {
      description: 'Wildcard attempt',
      owner: { github: 'tester' },
      record: { A: ['93.184.216.34'] }
    },
    config
  );
  assert.ok(wildcard.errors.some((e) => e.includes('Wildcard')));

  const reserved = validateDomainPayload(
    'admin',
    {
      description: 'Reserved name attempt',
      owner: { github: 'tester' },
      record: { A: ['93.184.216.34'] }
    },
    config
  );
  assert.ok(reserved.errors.some((e) => e.includes('reserved')));
});

test('Rejects brand impersonation phishing names', () => {
  const phishing = validateDomainPayload(
    'paypal-verify',
    {
      description: 'Suspicious brand lookalike',
      owner: { github: 'tester' },
      record: { A: ['93.184.216.34'] }
    },
    config
  );
  assert.ok(phishing.errors.some((e) => e.includes('brand/anti-phishing')));
});

test('Rejects GitHub Pages takeover mismatch without matching org repo', () => {
  const takeover = validateDomainPayload(
    'my-site',
    {
      description: 'Pointing to another user GitHub Pages without proof',
      owner: { github: 'attacker' },
      record: { CNAME: 'victim.github.io' }
    },
    config
  );
  assert.ok(takeover.errors.some((e) => e.includes('anti-takeover')));
});

test('Rejects self-referencing CNAME loops and URL protocols', () => {
  const loop = validateDomainPayload(
    'loop-test',
    {
      description: 'Testing DNS loop rejection',
      owner: { github: 'tester' },
      record: { CNAME: 'other.is-a.store' }
    },
    config
  );
  assert.ok(loop.errors.some((e) => e.includes('DNS loop')));

  const proto = validateDomainPayload(
    'proto-test',
    {
      description: 'Testing protocol rejection',
      owner: { github: 'tester' },
      record: { CNAME: 'https://tester.github.io' }
    },
    config
  );
  assert.ok(proto.errors.some((e) => e.includes('bare hostname')));
});

console.log(`\nCompleted test suite: ${passed} test(s) passed.`);
