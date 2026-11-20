(function (global) {
  'use strict';

  const GITHUB_USERNAME_RE = /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,37}[a-zA-Z0-9])?$/;
  const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])$/;
  const FQDN_RE = /^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

  function isValidIPv4(ip) {
    return IPV4_RE.test(ip);
  }

  function isPrivateOrReservedIPv4(ip) {
    if (!isValidIPv4(ip)) return true;
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    if (a === 192 && b === 168) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    return false;
  }

  function expandIPv6(ip) {
    const lower = String(ip).toLowerCase();
    if (!/^[0-9a-f:]+$/.test(lower)) return null;
    const halves = lower.split('::');
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    if (halves.length === 1 && left.length !== 8) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 0) return null;
    const full = [...left, ...Array(missing).fill('0'), ...right];
    if (full.length !== 8) return null;
    if (full.some((g) => g.length === 0 || g.length > 4)) return null;
    return full.map((g) => parseInt(g, 16));
  }

  function isValidIPv6(ip) {
    return expandIPv6(ip) !== null;
  }

  function isPrivateOrReservedIPv6(ip) {
    const groups = expandIPv6(ip);
    if (!groups) return true;
    if (groups.every((g) => g === 0)) return true;
    if (groups.slice(0, 7).every((g) => g === 0) && groups[7] === 1) return true;
    const [first, second] = groups;
    if ((first & 0xfe00) === 0xfc00) return true;
    if ((first & 0xffc0) === 0xfe80) return true;
    if ((first & 0xff00) === 0xff00) return true;
    if (first === 0x2001 && second === 0x0db8) return true;
    if (first === 0 && second === 0) return true;
    return false;
  }

  function isMaintainer(user, config) {
    if (!user || !Array.isArray(config?.maintainers)) return false;
    return config.maintainers.some((m) => m.toLowerCase() === user.toLowerCase());
  }

  function validateSubdomain(rawName, config, ownerGithub) {
    const errors = [];
    const name = String(rawName || '').trim();
    if (!name) return ['Subdomain name is required.'];
    if (name !== name.toLowerCase()) errors.push('Use lowercase letters only.');
    if (name.includes('*')) errors.push('Wildcard subdomains (*) are prohibited.');
    if (name.includes('.')) errors.push('Nested multi-level subdomains are not allowed.');

    const minLen = config?.limits?.minLabelLength ?? 2;
    const maxLen = config?.limits?.maxLabelLength ?? 63;
    if (name.length < minLen || name.length > maxLen) {
      errors.push(`Length must be between ${minLen} and ${maxLen} characters.`);
    }
    if (!LABEL_RE.test(name)) {
      errors.push('Only lowercase letters (a-z), digits (0-9), and interior hyphens (-) are allowed.');
    }
    if (name.startsWith('xn--')) {
      errors.push('Punycode labels (xn--) are blocked to prevent homograph spoofing.');
    }

    const maintainer = isMaintainer(ownerGithub, config);
    if (!maintainer && Array.isArray(config?.reservedNames) && config.reservedNames.includes(name)) {
      errors.push(`"${name}" is a reserved infrastructure subdomain.`);
    }
    if (!maintainer && Array.isArray(config?.blockedBrandKeywords)) {
      for (const brand of config.blockedBrandKeywords) {
        if (name === brand || name.includes(`-${brand}`) || name.includes(`${brand}-`)) {
          errors.push(`"${name}" matches restricted brand/anti-phishing keyword "${brand}".`);
        }
      }
    }

    return errors;
  }

  function validateHostname(target, label, config) {
    const errors = [];
    const val = String(target || '').trim();
    if (!val) return [`${label} is required.`];
    if (/^https?:\/\//i.test(val) || val.includes('/') || val.includes(':')) {
      return [`${label} must be a bare hostname without protocol, path, or port.`];
    }
    if (val.endsWith('.')) errors.push(`${label} must not end with a trailing dot.`);
    if (val.includes('*')) errors.push(`${label} cannot contain wildcards (*).`);
    if (isValidIPv4(val) || isValidIPv6(val)) {
      return [`${label} cannot be an IP address; choose A or AAAA instead.`];
    }
    if (val !== val.toLowerCase()) errors.push(`${label} must be lowercase.`);
    if (!FQDN_RE.test(val.toLowerCase())) {
      errors.push(`${label} "${val}" is not a valid hostname (FQDN).`);
    }
    const root = String(config?.rootDomain || '').toLowerCase();
    if (root && (val.toLowerCase() === root || val.toLowerCase().endsWith(`.${root}`))) {
      errors.push(`${label} cannot point back to ${root} (DNS loop).`);
    }
    for (const suffix of config?.disallowedTargetSuffixes || []) {
      if (val.toLowerCase().endsWith(suffix)) {
        errors.push(`${label} cannot use internal/reserved suffix "${suffix}".`);
      }
    }
    return errors;
  }

  function validateFormInput(input, config) {
    const errors = [];
    const subdomain = String(input.subdomain || '').trim();
    const github = String(input.github || '').trim();
    const email = String(input.email || '').trim();
    const description = String(input.description || '').trim();
    const repo = String(input.repo || '').trim();
    const recordType = input.recordType;
    const rawTarget = String(input.target || '').trim();
    const mxPriority = Number(input.mxPriority);
    const proxied = Boolean(input.proxied);

    errors.push(...validateSubdomain(subdomain, config, github));

    if (!github || !GITHUB_USERNAME_RE.test(github)) {
      errors.push('Enter a valid GitHub username.');
    }
    if (email && !EMAIL_RE.test(email)) {
      errors.push('Enter a valid email address or leave email blank.');
    }
    if (description.length < 5 || description.length > 200) {
      errors.push('Description must be between 5 and 200 characters.');
    }
    if (repo) {
      try {
        const u = new URL(repo);
        if (u.protocol !== 'https:') errors.push('Project / Repo URL must start with https://.');
      } catch {
        errors.push('Project / Repo URL is not a valid HTTPS URL.');
      }
    }

    const record = {};
    const items = rawTarget
      .split(/[\n,]+/)
      .map((s) => s.trim())
      .filter(Boolean);

    if (recordType === 'CNAME') {
      const target = rawTarget.trim();
      const hostErrors = validateHostname(target, 'CNAME target', config);
      errors.push(...hostErrors);
      if (hostErrors.length === 0 && target.endsWith('.github.io') && github) {
        const prefix = target.slice(0, -'.github.io'.length);
        if (prefix.toLowerCase() !== github.toLowerCase()) {
          const repoOk = repo.toLowerCase().startsWith(`https://github.com/${prefix.toLowerCase()}/`);
          if (!repoOk) {
            errors.push(
              `Anti-takeover guard: CNAME "${target}" does not match GitHub user "${github}". For an org site, add "https://github.com/${prefix}/..." in Project / Repo URL.`
            );
          }
        }
      }
      record.CNAME = target;
    } else if (recordType === 'A') {
      if (items.length === 0) errors.push('Enter at least one public IPv4 address.');
      if (items.length > 4) errors.push('Maximum 4 IPv4 addresses allowed.');
      for (const ip of items) {
        if (!isValidIPv4(ip)) errors.push(`"${ip}" is not a valid IPv4 address.`);
        else if (isPrivateOrReservedIPv4(ip)) errors.push(`"${ip}" is a private/reserved IPv4 address and is blocked.`);
      }
      record.A = [...new Set(items)];
    } else if (recordType === 'AAAA') {
      if (items.length === 0) errors.push('Enter at least one public IPv6 address.');
      if (items.length > 4) errors.push('Maximum 4 IPv6 addresses allowed.');
      for (const ip of items) {
        if (!isValidIPv6(ip)) errors.push(`"${ip}" is not a valid IPv6 address.`);
        else if (isPrivateOrReservedIPv6(ip)) errors.push(`"${ip}" is a private/reserved IPv6 address and is blocked.`);
      }
      record.AAAA = [...new Set(items)];
    } else if (recordType === 'TXT') {
      const lines = rawTarget
        .split(/\n+/)
        .map((s) => s.trim())
        .filter(Boolean);
      if (lines.length === 0) errors.push('Enter at least one TXT record value.');
      if (lines.length > 5) errors.push('Maximum 5 TXT records allowed.');
      for (const txt of lines) {
        if (txt.length > 255) errors.push('Each TXT value must be 255 characters or fewer.');
      }
      record.TXT = [...new Set(lines)];
    } else if (recordType === 'MX') {
      if (items.length === 0) errors.push('Enter at least one mail exchanger hostname.');
      if (items.length > 5) errors.push('Maximum 5 MX records allowed.');
      if (!Number.isInteger(mxPriority) || mxPriority < 0 || mxPriority > 65535) {
        errors.push('MX priority must be an integer between 0 and 65535.');
      }
      const mxList = [];
      for (const host of items) {
        errors.push(...validateHostname(host, 'MX target', config));
        mxList.push({ target: host, priority: Number.isInteger(mxPriority) ? mxPriority : 10 });
      }
      record.MX = mxList;
    }

    const payload = {
      description: description || 'Describe your website or project here',
      ...(repo ? { repo } : {}),
      owner: {
        github: github || 'your-github-username',
        ...(email ? { email } : {})
      },
      record
    };

    if (recordType === 'CNAME' || recordType === 'A' || recordType === 'AAAA') {
      payload.proxied = proxied;
    }

    return { errors, payload };
  }

  global.RegistryValidator = {
    validateSubdomain,
    validateFormInput,
    isMaintainer
  };
})(window);
