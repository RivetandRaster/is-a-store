'use strict';

const net = require('net');

const GITHUB_USERNAME_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/;
const FQDN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
const CONTROL_CHAR_RE = /[\u0000-\u001F\u007F]/;

function isPrivateOrReservedIPv4(ip) {
  if (net.isIPv4(ip) === false) return true;
  const parts = ip.split('.').map(Number);
  if (parts.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b, c] = parts;

  // 0.0.0.0/8 (This host)
  if (a === 0) return true;
  // 10.0.0.0/8 (RFC 1918 Private)
  if (a === 10) return true;
  // 100.64.0.0/10 (RFC 6598 CGNAT)
  if (a === 100 && b >= 64 && b <= 127) return true;
  // 127.0.0.0/8 (Loopback)
  if (a === 127) return true;
  // 169.254.0.0/16 (Link-local / Cloud metadata 169.254.169.254)
  if (a === 169 && b === 254) return true;
  // 172.16.0.0/12 (RFC 1918 Private)
  if (a === 172 && b >= 16 && b <= 31) return true;
  // 192.0.0.0/24, 192.0.2.0/24 (IETF Protocol / TEST-NET-1)
  if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
  // 192.168.0.0/16 (RFC 1918 Private)
  if (a === 192 && b === 168) return true;
  // 198.18.0.0/15 (Benchmarking)
  if (a === 198 && (b === 18 || b === 19)) return true;
  // 198.51.100.0/24 (TEST-NET-2)
  if (a === 198 && b === 51 && c === 100) return true;
  // 203.0.113.0/24 (TEST-NET-3)
  if (a === 203 && b === 0 && c === 113) return true;
  // 224.0.0.0/4 (Multicast) and 240.0.0.0/4 (Reserved / Broadcast)
  if (a >= 224) return true;

  return false;
}

function expandIPv6(ip) {
  const lower = ip.toLowerCase();
  if (lower.includes('.')) {
    // Reject IPv4-embedded IPv6 forms for simplicity & safety
    return null;
  }
  const halves = lower.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  if (halves.length === 1 && left.length !== 8) return null;
  const missing = 8 - (left.length + right.length);
  if (missing < 0) return null;
  const full = [...left, ...Array(missing).fill('0'), ...right];
  if (full.length !== 8) return null;
  return full.map((group) => parseInt(group, 16));
}

function isPrivateOrReservedIPv6(ip) {
  if (net.isIPv6(ip) === false) return true;
  const groups = expandIPv6(ip);
  if (!groups || groups.some((g) => Number.isNaN(g))) return true;

  const isAllZero = groups.every((g) => g === 0);
  if (isAllZero) return true; // ::
  const isLoopback = groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1;
  if (isLoopback) return true; // ::1

  const first = groups[0];
  const second = groups[1];
  // Unique Local fc00::/7
  if ((first & 0xfe00) === 0xfc00) return true;
  // Link-local fe80::/10
  if ((first & 0xffc0) === 0xfe80) return true;
  // Multicast ff00::/8
  if ((first & 0xff00) === 0xff00) return true;
  // Documentation 2001:db8::/32
  if (first === 0x2001 && second === 0x0db8) return true;
  // Unspecified / IPv4-mapped / Discard (first 4 groups 0)
  if (first === 0 && second === 0) return true;

  return false;
}

function isMaintainer(githubUser, config) {
  if (!githubUser || !Array.isArray(config.maintainers)) return false;
  return config.maintainers.some(
    (m) => m.toLowerCase() === String(githubUser).toLowerCase()
  );
}

function validateSubdomainName(name, config, ownerGithub) {
  const errors = [];
  if (typeof name !== 'string' || name.length === 0) {
    return ['Subdomain filename must be a non-empty string.'];
  }

  if (name !== name.toLowerCase()) {
    errors.push(`Subdomain "${name}" must be strictly lowercase.`);
  }

  if (name.includes('*')) {
    errors.push('Wildcard subdomains (*) are strictly prohibited.');
  }

  if (name.includes('.')) {
    errors.push('Nested multi-level subdomains are not permitted; use a single DNS label.');
  }

  const minLen = config.limits?.minLabelLength ?? 2;
  const maxLen = config.limits?.maxLabelLength ?? 63;
  if (name.length < minLen || name.length > maxLen) {
    errors.push(`Subdomain length must be between ${minLen} and ${maxLen} characters.`);
  }

  if (!LABEL_RE.test(name)) {
    errors.push(
      'Subdomain may only contain lowercase letters (a-z), digits (0-9), and interior hyphens (-).'
    );
  }

  if (name.startsWith('xn--')) {
    errors.push('Punycode/IDN labels (xn--) are disallowed to prevent homograph spoofing.');
  }

  const maintainer = isMaintainer(ownerGithub, config);

  if (!maintainer && Array.isArray(config.reservedNames) && config.reservedNames.includes(name)) {
    errors.push(`"${name}" is a reserved infrastructure or system subdomain.`);
  }

  if (!maintainer && Array.isArray(config.blockedBrandKeywords)) {
    for (const brand of config.blockedBrandKeywords) {
      if (name === brand || name.includes(`-${brand}`) || name.includes(`${brand}-`)) {
        errors.push(
          `Subdomain "${name}" matches restricted brand/anti-phishing keyword "${brand}".`
        );
      }
    }
  }

  return errors;
}

function validateHostnameTarget(target, fieldName, config) {
  const errors = [];
  if (typeof target !== 'string') {
    return [`${fieldName} must be a string.`];
  }

  if (/^https?:\/\//i.test(target) || target.includes('/') || target.includes(':')) {
    errors.push(`${fieldName} "${target}" must be a bare hostname (no protocol, path, or port).`);
    return errors;
  }

  if (target.endsWith('.')) {
    errors.push(`${fieldName} "${target}" must not include a trailing dot.`);
  }

  if (target.includes('*')) {
    errors.push(`${fieldName} must not contain wildcard characters (*).`);
  }

  if (net.isIP(target) !== 0) {
    errors.push(`${fieldName} "${target}" cannot be an IP address; use A or AAAA records instead.`);
    return errors;
  }

  const lower = target.toLowerCase();
  if (target !== lower) {
    errors.push(`${fieldName} "${target}" must be lowercase.`);
  }

  if (!FQDN_RE.test(lower)) {
    errors.push(`${fieldName} "${target}" is not a valid fully qualified domain name (FQDN).`);
    return errors;
  }

  const root = String(config.rootDomain || '').toLowerCase();
  if (root && (lower === root || lower.endsWith(`.${root}`))) {
    errors.push(`${fieldName} "${target}" cannot point back to ${root} (DNS loop risk).`);
  }

  const disallowed = config.disallowedTargetSuffixes || [];
  for (const suffix of disallowed) {
    if (lower.endsWith(suffix) || lower === suffix.slice(1)) {
      errors.push(`${fieldName} "${target}" uses disallowed internal/reserved suffix "${suffix}".`);
    }
  }

  return errors;
}

function validateDomainPayload(subdomain, data, config) {
  const errors = [];
  const warnings = [];

  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    return { errors: ['Root JSON value must be an object.'], warnings };
  }

  const allowedTopKeys = new Set([
    'description',
    'repo',
    'owner',
    'record',
    'proxied',
    'status',
    'suspensionReason'
  ]);
  for (const key of Object.keys(data)) {
    if (!allowedTopKeys.has(key)) {
      errors.push(`Unknown top-level property "${key}".`);
    }
  }

  // Validate owner first so maintainer exemption can be evaluated
  const ownerGithub = data.owner?.github;
  if (!data.owner || typeof data.owner !== 'object' || Array.isArray(data.owner)) {
    errors.push('Missing required "owner" object.');
  } else {
    const allowedOwnerKeys = new Set(['github', 'email']);
    for (const k of Object.keys(data.owner)) {
      if (!allowedOwnerKeys.has(k)) {
        errors.push(`Unknown property "owner.${k}".`);
      }
    }
    if (typeof ownerGithub !== 'string' || !GITHUB_USERNAME_RE.test(ownerGithub)) {
      errors.push('owner.github must be a valid GitHub username.');
    }
    if (data.owner.email !== undefined) {
      if (
        typeof data.owner.email !== 'string' ||
        data.owner.email.length > 120 ||
        !EMAIL_RE.test(data.owner.email)
      ) {
        errors.push('owner.email must be a valid email address.');
      }
    }
  }

  // Validate subdomain filename
  errors.push(...validateSubdomainName(subdomain, config, ownerGithub));

  // Validate description
  if (typeof data.description !== 'string') {
    errors.push('Missing required "description" string.');
  } else {
    const trimmed = data.description.trim();
    if (trimmed.length < 5 || trimmed.length > 200) {
      errors.push('description must be between 5 and 200 characters.');
    }
    if (CONTROL_CHAR_RE.test(data.description)) {
      errors.push('description must not contain control characters.');
    }
  }

  // Validate optional repo URL
  if (data.repo !== undefined) {
    if (typeof data.repo !== 'string' || !data.repo.startsWith('https://') || data.repo.length > 250) {
      errors.push('repo must be a valid https:// URL (max 250 chars).');
    } else {
      try {
        const parsed = new URL(data.repo);
        if (parsed.protocol !== 'https:') {
          errors.push('repo URL must use HTTPS.');
        }
      } catch {
        errors.push('repo is not a valid URL.');
      }
    }
  }

  // Validate status & suspensionReason
  const status = data.status ?? 'active';
  if (status !== 'active' && status !== 'suspended') {
    errors.push('status must be either "active" or "suspended".');
  }
  if (status === 'suspended') {
    if (
      typeof data.suspensionReason !== 'string' ||
      data.suspensionReason.trim().length < 5
    ) {
      errors.push('suspensionReason (min 5 chars) is required when status is "suspended".');
    }
  } else if (data.suspensionReason !== undefined) {
    errors.push('suspensionReason is only allowed when status is "suspended".');
  }

  // Validate proxied
  if (data.proxied !== undefined && typeof data.proxied !== 'boolean') {
    errors.push('proxied must be a boolean.');
  }

  // Validate DNS records
  if (!data.record || typeof data.record !== 'object' || Array.isArray(data.record)) {
    errors.push('Missing required "record" object.');
    return { errors, warnings };
  }

  const supported = new Set(config.supportedRecords || ['CNAME', 'A', 'AAAA', 'TXT', 'MX']);
  const recordKeys = Object.keys(data.record);
  if (recordKeys.length === 0) {
    errors.push('record object must contain at least one DNS record type.');
    return { errors, warnings };
  }

  for (const key of recordKeys) {
    if (!supported.has(key)) {
      errors.push(`Unsupported DNS record type "${key}". Allowed: ${[...supported].join(', ')}.`);
    }
  }

  // RFC 1034 / RFC 2181: CNAME exclusivity
  if (data.record.CNAME !== undefined && recordKeys.length > 1) {
    errors.push(
      'Invalid DNS combination: CNAME cannot coexist with A, AAAA, TXT, or MX records on the same subdomain (RFC 1034 §3.6.2).'
    );
  }

  // Cloudflare proxy only applies to A, AAAA, CNAME
  if (data.proxied === true) {
    const hasProxyable =
      data.record.A !== undefined ||
      data.record.AAAA !== undefined ||
      data.record.CNAME !== undefined;
    if (!hasProxyable) {
      errors.push('proxied: true requires an A, AAAA, or CNAME record.');
    }
  }

  const limits = config.limits?.maxRecordsPerType || { A: 4, AAAA: 4, CNAME: 1, TXT: 5, MX: 5 };

  // Validate A
  if (data.record.A !== undefined) {
    if (!Array.isArray(data.record.A) || data.record.A.length === 0) {
      errors.push('record.A must be a non-empty array of IPv4 strings.');
    } else {
      if (data.record.A.length > limits.A) {
        errors.push(`record.A supports at most ${limits.A} addresses.`);
      }
      const seen = new Set();
      for (const ip of data.record.A) {
        if (typeof ip !== 'string' || !net.isIPv4(ip)) {
          errors.push(`record.A contains invalid IPv4 address "${ip}".`);
        } else if (isPrivateOrReservedIPv4(ip)) {
          errors.push(`record.A address "${ip}" is private, loopback, or reserved and is blocked.`);
        } else if (seen.has(ip)) {
          errors.push(`record.A contains duplicate IPv4 address "${ip}".`);
        }
        seen.add(ip);
      }
    }
  }

  // Validate AAAA
  if (data.record.AAAA !== undefined) {
    if (!Array.isArray(data.record.AAAA) || data.record.AAAA.length === 0) {
      errors.push('record.AAAA must be a non-empty array of IPv6 strings.');
    } else {
      if (data.record.AAAA.length > limits.AAAA) {
        errors.push(`record.AAAA supports at most ${limits.AAAA} addresses.`);
      }
      const seen = new Set();
      for (const ip of data.record.AAAA) {
        if (typeof ip !== 'string' || !net.isIPv6(ip)) {
          errors.push(`record.AAAA contains invalid IPv6 address "${ip}".`);
        } else if (isPrivateOrReservedIPv6(ip)) {
          errors.push(`record.AAAA address "${ip}" is private, loopback, or reserved and is blocked.`);
        } else if (seen.has(ip)) {
          errors.push(`record.AAAA contains duplicate IPv6 address "${ip}".`);
        }
        seen.add(ip);
      }
    }
  }

  // Validate CNAME
  if (data.record.CNAME !== undefined) {
    const cnameErrors = validateHostnameTarget(data.record.CNAME, 'record.CNAME', config);
    errors.push(...cnameErrors);

    // Anti-takeover guard for GitHub Pages
    if (
      cnameErrors.length === 0 &&
      typeof ownerGithub === 'string' &&
      data.record.CNAME.endsWith('.github.io')
    ) {
      const ghPrefix = data.record.CNAME.slice(0, -'.github.io'.length);
      if (ghPrefix.toLowerCase() !== ownerGithub.toLowerCase()) {
        const repoMatches =
          typeof data.repo === 'string' &&
          data.repo.toLowerCase().startsWith(`https://github.com/${ghPrefix.toLowerCase()}/`);
        if (!repoMatches) {
          errors.push(
            `GitHub Pages anti-takeover check: CNAME "${data.record.CNAME}" does not match owner.github "${ownerGithub}". If this is an organization site, include a matching "repo": "https://github.com/${ghPrefix}/..." URL.`
          );
        }
      }
    }
  }

  // Validate TXT
  if (data.record.TXT !== undefined) {
    if (!Array.isArray(data.record.TXT) || data.record.TXT.length === 0) {
      errors.push('record.TXT must be a non-empty array of strings.');
    } else {
      if (data.record.TXT.length > limits.TXT) {
        errors.push(`record.TXT supports at most ${limits.TXT} entries.`);
      }
      const maxTxt = config.limits?.maxTxtLength ?? 255;
      const seen = new Set();
      for (const val of data.record.TXT) {
        if (typeof val !== 'string' || val.trim().length === 0) {
          errors.push('record.TXT entries must be non-empty strings.');
        } else {
          if (val.length > maxTxt) {
            errors.push(`record.TXT entry exceeds maximum length of ${maxTxt} characters.`);
          }
          if (CONTROL_CHAR_RE.test(val)) {
            errors.push('record.TXT entry must not contain control characters.');
          }
          if (seen.has(val)) {
            errors.push('record.TXT contains duplicate entries.');
          }
          seen.add(val);
        }
      }
    }
  }

  // Validate MX
  if (data.record.MX !== undefined) {
    if (!Array.isArray(data.record.MX) || data.record.MX.length === 0) {
      errors.push('record.MX must be a non-empty array of { target, priority } objects.');
    } else {
      if (data.record.MX.length > limits.MX) {
        errors.push(`record.MX supports at most ${limits.MX} entries.`);
      }
      const seenTargets = new Set();
      for (const entry of data.record.MX) {
        if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
          errors.push('Each record.MX entry must be an object with "target" and "priority".');
          continue;
        }
        const keys = Object.keys(entry);
        if (keys.some((k) => k !== 'target' && k !== 'priority')) {
          errors.push('record.MX entries only allow "target" and "priority" properties.');
        }
        errors.push(...validateHostnameTarget(entry.target, 'record.MX.target', config));
        if (
          typeof entry.priority !== 'number' ||
          !Number.isInteger(entry.priority) ||
          entry.priority < 0 ||
          entry.priority > 65535
        ) {
          errors.push('record.MX.priority must be an integer between 0 and 65535.');
        }
        if (typeof entry.target === 'string') {
          if (seenTargets.has(entry.target)) {
            errors.push(`record.MX contains duplicate target "${entry.target}".`);
          }
          seenTargets.add(entry.target);
        }
      }
    }
  }

  return { errors, warnings };
}

module.exports = {
  isPrivateOrReservedIPv4,
  isPrivateOrReservedIPv6,
  isMaintainer,
  validateSubdomainName,
  validateHostnameTarget,
  validateDomainPayload
};
