(function () {
  'use strict';

  const state = {
    config: null,
    registryLoaded: false,
    registryError: null,
    domains: [],
    domainMap: new Map(),
    pendingMap: new Map(),
    pendingLoaded: false,
    activeFilter: 'ALL',
    searchQuery: ''
  };

  const DOC_CONTENT = {
    registration: `
      <h3>How to Register a Subdomain</h3>
      <p>Every subdomain in this registry is represented by a single JSON file inside <code>registry/domains/&lt;subdomain&gt;.json</code>. There is no account signup or proprietary backend — GitHub Pull Requests serve as both authentication and audit trail.</p>
      <h4>Step-by-step (Android Browser &amp; Desktop)</h4>
      <ol>
        <li><strong>Check availability</strong> using the search bar above. Never submit a name already listed as <em>Registered</em> or <em>Pending approval</em>.</li>
        <li><strong>Deploy your site first</strong> (for example on GitHub Pages, Cloudflare Pages, Vercel, or Netlify) so maintainers can verify it is not empty or parked.</li>
        <li><strong>Fill in the Registration Builder</strong> and tap <em>Open in GitHub Editor &amp; Submit PR</em>.</li>
        <li>GitHub automatically forks the repository under your account and opens a Pull Request with your JSON pre-filled.</li>
        <li>Wait for the automated <code>Validate Subdomain PR</code> check to turn green, then wait for maintainer review.</li>
      </ol>
      <h4>Root Domain Feasibility &amp; ₹0 Budget Notice</h4>
      <p><code>.store</code> is a commercial Top-Level Domain operated by Radix and cannot be registered for ₹0. GitHub Pages hosts the frontend for free at <code>*.github.io</code>, and Cloudflare DNS is free once you own or delegate a domain. To run live DNS on a ₹0 budget, obtain a free NS-delegated third-level domain (such as <code>eu.org</code> or DigitalPlat <code>dpdns.org</code>), point its nameservers to Cloudflare Free DNS, update <code>rootDomain</code> in <code>config/registry.config.json</code>, and add <code>CF_API_TOKEN</code> + <code>CF_ZONE_ID</code> to GitHub Actions Secrets.</p>
      <p><a href="https://github.com/RivetandRaster/is-a-store/blob/main/docs/registration.md" target="_blank" rel="noopener noreferrer">Read full docs/registration.md on GitHub &rarr;</a></p>
    `,
    dns: `
      <h3>Supported DNS Records &amp; Security Rules</h3>
      <ul>
        <li><strong>CNAME</strong>: Single canonical hostname (e.g., <code>username.github.io</code>). Cannot coexist with any other record type on the same subdomain (RFC 1034 &sect;3.6.2).</li>
        <li><strong>A</strong>: Up to 4 public IPv4 addresses. Private, loopback, CGNAT, link-local, and cloud metadata IPs (<code>10/8</code>, <code>127/8</code>, <code>169.254/16</code>, <code>172.16/12</code>, <code>192.168/16</code>) are blocked.</li>
        <li><strong>AAAA</strong>: Up to 4 public IPv6 addresses. Loopback (<code>::1</code>), ULA (<code>fc00::/7</code>), and link-local (<code>fe80::/10</code>) are blocked.</li>
        <li><strong>TXT</strong>: Up to 5 verification/metadata strings (max 255 chars each).</li>
        <li><strong>MX</strong>: Up to 5 mail exchanger objects with <code>target</code> hostname and integer <code>priority</code> (0–65535).</li>
      </ul>
      <h4>Anti-Takeover Protections</h4>
      <p>If your <code>CNAME</code> targets <code>&lt;user&gt;.github.io</code>, the username must match <code>owner.github</code> (or reference a matching GitHub organization URL in <code>repo</code>). Wildcard records (<code>*</code>), punycode homographs (<code>xn--</code>), and self-referencing DNS loops are automatically rejected.</p>
      <pre><code>{
  "description": "Personal indie store template",
  "repo": "https://github.com/octocat/shop",
  "owner": { "github": "octocat" },
  "record": { "CNAME": "octocat.github.io" },
  "proxied": false
}</code></pre>
      <p><a href="https://github.com/RivetandRaster/is-a-store/blob/main/docs/dns.md" target="_blank" rel="noopener noreferrer">Read full docs/dns.md on GitHub &rarr;</a></p>
    `,
    abuse: `
      <h3>Anti-Abuse Rules, Suspension &amp; Removal</h3>
      <p>To protect users and keep the root domain off DNS blocklists, the following uses are strictly prohibited:</p>
      <ul>
        <li>Phishing, credential harvesting, brand impersonation, or deceptive login pages.</li>
        <li>Malware distribution, command-and-control (C2) endpoints, or scam/fraud storefronts.</li>
        <li>Domain squatting, bulk registration (capped at 3 subdomains per GitHub user), or parked/blank sites.</li>
        <li>Illegal content, copyright piracy hubs, or spam-sending mail infrastructure.</li>
      </ul>
      <h4>Suspension &amp; Takedown Process</h4>
      <p>Anyone can report an abusive subdomain via the <a href="https://github.com/RivetandRaster/is-a-store/issues/new?template=abuse-report.yml" target="_blank" rel="noopener noreferrer">Abuse Report Issue Template</a>. Maintainers verify the report and set <code>"status": "suspended"</code> with a <code>suspensionReason</code>. On merge, <code>scripts/sync-dns.js</code> immediately deletes the DNS records from Cloudflare while keeping the filename locked so the attacker cannot re-register it.</p>
      <p><a href="https://github.com/RivetandRaster/is-a-store/blob/main/docs/abuse.md" target="_blank" rel="noopener noreferrer">Read full docs/abuse.md on GitHub &rarr;</a></p>
    `,
    legal: `
      <h3>Domain Ownership, Terms of Service &amp; Privacy</h3>
      <h4>Ownership &amp; Revocation</h4>
      <p>Subdomains are granted as a revocable, non-transferable license for active projects. Ownership is tied to your GitHub account listed in <code>owner.github</code>. You may update or delete your record at any time via Pull Request from that GitHub account. Inactive or dangling subdomains (pointing to deleted hosting accounts) may be revoked to prevent subdomain takeover.</p>
      <h4>Privacy Policy</h4>
      <p>This website uses zero third-party analytics, zero cookies, and zero tracking scripts. Theme preference is stored locally in your browser's <code>localStorage</code>. However, any JSON file you submit via GitHub Pull Request becomes part of a <strong>public Git repository and permanent Git history</strong>. Providing <code>owner.email</code> is strictly optional — omit it if you do not want your email publicly visible.</p>
      <p><a href="https://github.com/RivetandRaster/is-a-store/blob/main/docs/terms.md" target="_blank" rel="noopener noreferrer">Terms of Service</a> &middot; <a href="https://github.com/RivetandRaster/is-a-store/blob/main/docs/privacy.md" target="_blank" rel="noopener noreferrer">Privacy Policy</a></p>
    `,
    troubleshooting: `
      <h3>Troubleshooting Common Errors</h3>
      <ul>
        <li><strong>"CNAME cannot coexist with TXT/A/AAAA/MX"</strong>: Remove extra record types or switch from CNAME to A/AAAA records.</li>
        <li><strong>"GitHub Pages anti-takeover check failed"</strong>: Ensure <code>owner.github</code> matches the username in <code>&lt;user&gt;.github.io</code>, or add <code>"repo": "https://github.com/&lt;org&gt;/&lt;repo&gt;"</code>.</li>
        <li><strong>"Private/reserved IP blocked"</strong>: You entered a local address like <code>127.0.0.1</code> or <code>192.168.x.x</code>. Use your host's public IPv4/IPv6 address.</li>
        <li><strong>GitHub Pages HTTPS certificate stuck</strong>: Set <code>"proxied": false</code> in your JSON and add a <code>CNAME</code> file containing your full subdomain inside your website repository.</li>
      </ul>
      <p><a href="https://github.com/RivetandRaster/is-a-store/blob/main/docs/troubleshooting.md" target="_blank" rel="noopener noreferrer">Read full docs/troubleshooting.md on GitHub &rarr;</a></p>
    `
  };

  function el(id) {
    return document.getElementById(id);
  }

  function initTheme() {
    const saved = localStorage.getItem('is-a-store-theme');
    const prefersLight = window.matchMedia('(prefers-color-scheme: light)').matches;
    const theme = saved || (prefersLight ? 'light' : 'dark');
    applyTheme(theme);

    el('theme-toggle').addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      localStorage.setItem('is-a-store-theme', next);
      applyTheme(next);
    });
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const icon = el('theme-icon');
    if (icon) icon.innerHTML = theme === 'dark' ? '&#9728;' : '&#9790;';
  }

  async function loadConfigAndRegistry() {
    try {
      const [cfgRes, idxRes] = await Promise.all([
        fetch('config/registry.config.json', { cache: 'no-cache' }),
        fetch('registry/index.json', { cache: 'no-cache' })
      ]);

      if (!cfgRes.ok) throw new Error(`Could not load config (${cfgRes.status})`);
      if (!idxRes.ok) throw new Error(`Could not load registry/index.json (${idxRes.status})`);

      state.config = await cfgRes.json();
      const indexData = await idxRes.json();

      if (!Array.isArray(indexData.domains)) {
        throw new Error('Malformed registry/index.json payload.');
      }

      state.domains = indexData.domains;
      state.domainMap = new Map(indexData.domains.map((d) => [d.subdomain.toLowerCase(), d]));
      state.registryLoaded = true;
      state.registryError = null;
      applyConfigToUI(indexData);
    } catch (err) {
      state.registryLoaded = false;
      state.registryError = err.message;
      const errBox = el('directory-error');
      errBox.textContent = `Unable to load verified registry data (${err.message}). Availability checks are paused so no subdomain is falsely marked available.`;
      errBox.hidden = false;
      el('stat-total').textContent = 'ERR';
      el('stat-total-meta').textContent = 'Registry index failed to load';
    }
  }

  function applyConfigToUI(indexData) {
    const cfg = state.config;
    const root = cfg.rootDomain;
    el('brand-domain').textContent = root;
    el('footer-brand').textContent = root;
    el('hero-example-domain').textContent = `yourname.${root}`;
    el('hero-domain-suffix').textContent = `.${root}`;
    el('reg-domain-suffix').textContent = `.${root}`;
    el('repo-header-link').href = cfg.repository.url;

    const modePill = el('mode-pill');
    const dnsModeEl = el('stat-dns-mode');
    const dnsMetaEl = el('stat-dns-meta');

    if (cfg.dnsLiveMode) {
      modePill.textContent = 'Live DNS';
      dnsModeEl.textContent = 'Live';
      dnsMetaEl.textContent = `Cloudflare DNS active on ${root}`;
      el('staging-banner').hidden = true;
    } else {
      modePill.textContent = 'Staging';
      dnsModeEl.textContent = 'Staging';
      dnsMetaEl.textContent = 'Index live; awaiting root domain DNS';
      el('staging-banner-text').textContent = cfg.dnsStatusNote;
      el('staging-banner').hidden = false;
    }

    const active = state.domains.filter((d) => d.status !== 'suspended').length;
    el('stat-total').textContent = String(state.domains.length);
    el('stat-total-meta').textContent = `${active} active · updated ${new Date(indexData.generatedAt).toLocaleDateString()}`;
    el('stat-records').textContent = String((cfg.supportedRecords || []).length);
  }

  async function loadPendingPRs() {
    if (!state.config?.repository) return;
    const { owner, name } = state.config.repository;
    const cacheKey = `pending-prs:${owner}/${name}`;
    const cachedRaw = sessionStorage.getItem(cacheKey);
    if (cachedRaw) {
      try {
        const cached = JSON.parse(cachedRaw);
        if (Date.now() - cached.ts < 5 * 60 * 1000) {
          populatePending(cached.items);
          return;
        }
      } catch {
        sessionStorage.removeItem(cacheKey);
      }
    }

    try {
      const res = await fetch(
        `https://api.github.com/repos/${owner}/${name}/pulls?state=open&per_page=100`,
        { headers: { Accept: 'application/vnd.github+json' } }
      );
      if (!res.ok) throw new Error(`GitHub API ${res.status}`);
      const pulls = await res.json();
      const items = pulls.map((pr) => ({
        number: pr.number,
        title: pr.title,
        url: pr.html_url,
        user: pr.user?.login || 'unknown',
        headRef: pr.head?.ref || ''
      }));
      sessionStorage.setItem(cacheKey, JSON.stringify({ ts: Date.now(), items }));
      populatePending(items);
    } catch {
      state.pendingLoaded = false;
      el('stat-pending').textContent = 'N/A';
      el('stat-pending-meta').textContent = 'GitHub API rate-limited or offline';
    }
  }

  function extractSubdomainHints(pr) {
    const hints = new Set();
    const root = state.config?.rootDomain || 'is-a.store';
    const text = `${pr.title} ${pr.headRef}`.toLowerCase();
    const fqdnRegex = new RegExp(`([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\\.${root.replace(/\./g, '\\.')}`, 'g');
    let m;
    while ((m = fqdnRegex.exec(text)) !== null) hints.add(m[1]);
    const fileRegex = /registry\/domains\/([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.json/g;
    while ((m = fileRegex.exec(text)) !== null) hints.add(m[1]);
    const jsonRegex = /\b([a-z0-9][a-z0-9-]{1,61}[a-z0-9])\.json\b/g;
    while ((m = jsonRegex.exec(text)) !== null) hints.add(m[1]);
    return [...hints];
  }

  function populatePending(items) {
    state.pendingMap.clear();
    for (const pr of items) {
      for (const sub of extractSubdomainHints(pr)) {
        state.pendingMap.set(sub, pr);
      }
    }
    state.pendingLoaded = true;
    el('stat-pending').textContent = String(items.length);
    el('stat-pending-meta').textContent = items.length === 1 ? '1 open PR on GitHub' : `${items.length} open PRs on GitHub`;
    updateBuilder();
  }

  function evaluateSubdomainStatus(rawName, ownerGithub) {
    const name = String(rawName || '').trim();
    if (!name) {
      return { status: 'empty', label: 'Enter a name', message: '2–63 chars: lowercase letters, digits, and interior hyphens.' };
    }

    const validationErrors = window.RegistryValidator.validateSubdomain(name, state.config, ownerGithub);
    if (validationErrors.length > 0) {
      return { status: 'invalid', label: 'Invalid', message: validationErrors[0], errors: validationErrors };
    }

    if (!state.registryLoaded) {
      return {
        status: 'unverified',
        label: 'Unverified',
        message: 'Registry index could not be loaded — cannot confirm availability.'
      };
    }

    const existing = state.domainMap.get(name);
    if (existing) {
      return {
        status: 'registered',
        label: 'Registered',
        message: `Already registered by @${existing.owner} (${existing.recordTypes.join('/')} -> ${existing.destination}).`,
        record: existing
      };
    }

    const pendingPr = state.pendingMap.get(name);
    if (pendingPr) {
      return {
        status: 'pending',
        label: 'Pending approval',
        message: `Requested in open Pull Request #${pendingPr.number} by @${pendingPr.user}.`,
        pr: pendingPr
      };
    }

    const note = state.pendingLoaded
      ? `Confirmed not in registry or open PRs.`
      : `Not in registry index (verify open PRs on GitHub before submitting).`;
    return {
      status: 'available',
      label: 'Available',
      message: `${name}.${state.config.rootDomain} is available. ${note}`
    };
  }

  function setupHeroChecker() {
    const form = el('hero-search-form');
    const input = el('hero-subdomain-input');
    const resultBox = el('hero-check-result');

    function runCheck() {
      const val = input.value.trim();
      if (!val) {
        resultBox.hidden = true;
        return;
      }
      const res = evaluateSubdomainStatus(val, '');
      resultBox.hidden = false;
      resultBox.className = 'check-result';
      resultBox.innerHTML = '';

      const left = document.createElement('div');
      const strong = document.createElement('strong');
      strong.textContent = `${res.label}: `;
      const span = document.createElement('span');
      span.textContent = res.message;
      left.append(strong, span);
      resultBox.appendChild(left);

      if (res.status === 'available') {
        resultBox.classList.add('is-available');
        const claimBtn = document.createElement('a');
        claimBtn.href = '#register';
        claimBtn.className = 'btn btn-primary btn-sm';
        claimBtn.textContent = 'Configure & Claim';
        claimBtn.addEventListener('click', () => {
          el('reg-subdomain').value = val;
          updateBuilder();
        });
        resultBox.appendChild(claimBtn);
      } else if (res.status === 'registered') {
        resultBox.classList.add('is-registered');
        const inspectBtn = document.createElement('button');
        inspectBtn.type = 'button';
        inspectBtn.className = 'btn btn-secondary btn-sm';
        inspectBtn.textContent = 'Inspect Record';
        inspectBtn.addEventListener('click', () => openRecordModal(res.record));
        resultBox.appendChild(inspectBtn);
      } else if (res.status === 'pending') {
        resultBox.classList.add('is-pending');
        const prLink = document.createElement('a');
        prLink.href = res.pr.url;
        prLink.target = '_blank';
        prLink.rel = 'noopener noreferrer';
        prLink.className = 'btn btn-secondary btn-sm';
        prLink.textContent = `View PR #${res.pr.number}`;
        resultBox.appendChild(prLink);
      } else {
        resultBox.classList.add('is-invalid');
      }
    }

    form.addEventListener('submit', (e) => {
      e.preventDefault();
      runCheck();
    });
    input.addEventListener('input', () => {
      if (input.value.trim().length >= 2) runCheck();
      else resultBox.hidden = true;
    });
  }

  function updateRecordTypeUI() {
    const type = el('reg-record-type').value;
    const label = el('reg-target-label');
    const hint = el('reg-target-hint');
    const targetInput = el('reg-target');
    const mxGroup = el('mx-priority-group');
    const proxiedGroup = el('proxied-group');

    mxGroup.hidden = type !== 'MX';
    proxiedGroup.hidden = type === 'TXT' || type === 'MX';

    if (type === 'CNAME') {
      label.innerHTML = 'Target Hostname (CNAME) <span class="req">*</span>';
      targetInput.placeholder = 'octocat.github.io';
      hint.innerHTML = 'Bare hostname only — no <code>https://</code>, path, or trailing dot. Cannot be combined with other record types.';
    } else if (type === 'A') {
      label.innerHTML = 'Public IPv4 Address(es) <span class="req">*</span>';
      targetInput.placeholder = '185.199.108.153\n185.199.109.153';
      hint.textContent = 'Up to 4 public IPv4 addresses (separated by commas or new lines). Private IPs are blocked.';
    } else if (type === 'AAAA') {
      label.innerHTML = 'Public IPv6 Address(es) <span class="req">*</span>';
      targetInput.placeholder = '2606:50c0:8000::153';
      hint.textContent = 'Up to 4 public IPv6 addresses (separated by commas or new lines).';
    } else if (type === 'TXT') {
      label.innerHTML = 'TXT Record Value(s) <span class="req">*</span>';
      targetInput.placeholder = 'google-site-verification=abc123...';
      hint.textContent = 'Up to 5 TXT entries, one per line (max 255 characters each).';
    } else if (type === 'MX') {
      label.innerHTML = 'Mail Exchanger Hostname(s) <span class="req">*</span>';
      targetInput.placeholder = 'mx1.improvmx.com';
      hint.textContent = 'Up to 5 valid FQDNs (comma or newline separated) paired with the priority value.';
    }
  }

  function updateBuilder() {
    if (!state.config) return;
    const subdomain = el('reg-subdomain').value.trim();
    const github = el('reg-github').value.trim();
    const email = el('reg-email').value.trim();
    const description = el('reg-description').value.trim();
    const repo = el('reg-repo').value.trim();
    const recordType = el('reg-record-type').value;
    const target = el('reg-target').value.trim();
    const mxPriority = el('reg-mx-priority').value;
    const proxied = el('reg-proxied').checked;

    const availability = evaluateSubdomainStatus(subdomain, github);
    const pill = el('reg-availability-pill');
    const msg = el('reg-availability-msg');
    pill.textContent = availability.label;
    pill.className = 'pill ' + (
      availability.status === 'available' ? 'pill-success' :
      availability.status === 'registered' ? 'pill-info' :
      availability.status === 'pending' ? 'pill-warn' :
      availability.status === 'invalid' || availability.status === 'unverified' ? 'pill-danger' :
      'pill-neutral'
    );
    msg.textContent = availability.message;

    const { errors, payload } = window.RegistryValidator.validateFormInput(
      { subdomain, github, email, description, repo, recordType, target, mxPriority, proxied },
      state.config
    );

    const allErrors = [...errors];
    if (availability.status === 'registered' || availability.status === 'pending' || availability.status === 'unverified') {
      allErrors.unshift(availability.message);
    }

    const safeFileName = subdomain || 'your-subdomain';
    el('output-filepath').textContent = `registry/domains/${safeFileName}.json`;
    const jsonString = JSON.stringify(payload, null, 2) + '\n';
    el('json-preview').textContent = jsonString;

    const hasUserInput = Boolean(subdomain || github || description || target);
    const isReady = allErrors.length === 0 && availability.status === 'available';

    const errBox = el('reg-errors');
    if (hasUserInput && allErrors.length > 0) {
      errBox.hidden = false;
      errBox.innerHTML = '<strong>Fix the following before submitting:</strong>';
      const ul = document.createElement('ul');
      for (const e of [...new Set(allErrors)]) {
        const li = document.createElement('li');
        li.textContent = e;
        ul.appendChild(li);
      }
      errBox.appendChild(ul);
    } else {
      errBox.hidden = true;
      errBox.innerHTML = '';
    }

    const validBadge = el('output-valid-badge');
    const ghBtn = el('btn-open-github');
    const copyBtn = el('btn-copy-json');
    const dlBtn = el('btn-download-json');

    if (isReady) {
      validBadge.textContent = 'Ready for PR';
      validBadge.className = 'pill pill-success';
      const { owner, name, branch } = state.config.repository;
      const ghUrl =
        `https://github.com/${owner}/${name}/new/${branch}` +
        `?filename=${encodeURIComponent(`registry/domains/${subdomain}.json`)}` +
        `&value=${encodeURIComponent(jsonString)}` +
        `&message=${encodeURIComponent(`feat(domain): register ${subdomain}.${state.config.rootDomain}`)}`;
      ghBtn.href = ghUrl;
      ghBtn.classList.remove('disabled');
      ghBtn.setAttribute('aria-disabled', 'false');
      copyBtn.disabled = false;
      dlBtn.disabled = false;
    } else {
      validBadge.textContent = hasUserInput ? 'Validation Errors' : 'Incomplete';
      validBadge.className = hasUserInput ? 'pill pill-danger' : 'pill pill-neutral';
      ghBtn.href = '#';
      ghBtn.classList.add('disabled');
      ghBtn.setAttribute('aria-disabled', 'true');
      copyBtn.disabled = true;
      dlBtn.disabled = true;
    }
  }

  function setupBuilder() {
    const fields = [
      'reg-subdomain',
      'reg-github',
      'reg-email',
      'reg-description',
      'reg-repo',
      'reg-record-type',
      'reg-target',
      'reg-mx-priority',
      'reg-proxied'
    ];
    for (const id of fields) {
      el(id).addEventListener('input', updateBuilder);
      el(id).addEventListener('change', () => {
        if (id === 'reg-record-type') updateRecordTypeUI();
        updateBuilder();
      });
    }

    el('btn-copy-json').addEventListener('click', async () => {
      const text = el('json-preview').textContent;
      try {
        await navigator.clipboard.writeText(text);
        const btn = el('btn-copy-json');
        const old = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = old; }, 1600);
      } catch {
        alert('Clipboard permission blocked. Select and copy the JSON directly.');
      }
    });

    el('btn-download-json').addEventListener('click', () => {
      const sub = el('reg-subdomain').value.trim() || 'subdomain';
      const blob = new Blob([el('json-preview').textContent], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${sub}.json`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
    });

    updateRecordTypeUI();
  }

  function renderDirectory() {
    const tbody = el('directory-tbody');
    tbody.innerHTML = '';

    if (!state.registryLoaded) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'empty-cell';
      td.textContent = 'Registry index unavailable.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const q = state.searchQuery.toLowerCase();
    const filtered = state.domains.filter((d) => {
      const typeMatch = state.activeFilter === 'ALL' || d.recordTypes.includes(state.activeFilter);
      if (!typeMatch) return false;
      if (!q) return true;
      return (
        d.fqdn.toLowerCase().includes(q) ||
        d.destination.toLowerCase().includes(q) ||
        d.owner.toLowerCase().includes(q) ||
        (d.description || '').toLowerCase().includes(q)
      );
    });

    el('directory-count').textContent = `Showing ${filtered.length} of ${state.domains.length} registered subdomain(s).`;

    if (filtered.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'empty-cell';
      td.textContent = 'No matching subdomains found.';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    for (const d of filtered) {
      const tr = document.createElement('tr');

      const tdSub = document.createElement('td');
      tdSub.className = 'mono-cell';
      const strong = document.createElement('strong');
      strong.textContent = d.fqdn;
      tdSub.appendChild(strong);

      const tdType = document.createElement('td');
      for (const t of d.recordTypes) {
        const badge = document.createElement('span');
        badge.className = 'pill pill-neutral';
        badge.style.marginRight = '0.25rem';
        badge.textContent = t;
        tdType.appendChild(badge);
      }

      const tdDest = document.createElement('td');
      tdDest.className = 'mono-cell';
      tdDest.textContent = d.destination;

      const tdOwner = document.createElement('td');
      const ownerLink = document.createElement('a');
      ownerLink.href = `https://github.com/${encodeURIComponent(d.owner)}`;
      ownerLink.target = '_blank';
      ownerLink.rel = 'noopener noreferrer';
      ownerLink.textContent = `@${d.owner}`;
      tdOwner.appendChild(ownerLink);

      const tdStatus = document.createElement('td');
      const stPill = document.createElement('span');
      stPill.className =
        'pill ' +
        (d.status === 'active'
          ? 'pill-success'
          : d.status === 'suspended'
          ? 'pill-danger'
          : 'pill-warn');
      stPill.textContent =
        d.status === 'active'
          ? 'Active DNS'
          : d.status === 'suspended'
          ? 'Suspended'
          : 'Indexed (Staging)';
      tdStatus.appendChild(stPill);

      const tdAct = document.createElement('td');
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'btn btn-ghost btn-sm';
      btn.textContent = 'Inspect';
      btn.addEventListener('click', () => openRecordModal(d));
      tdAct.appendChild(btn);

      tr.append(tdSub, tdType, tdDest, tdOwner, tdStatus, tdAct);
      tbody.appendChild(tr);
    }
  }

  function setupDirectoryControls() {
    el('dir-search').addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim();
      renderDirectory();
    });

    document.querySelectorAll('.chip[data-filter]').forEach((chip) => {
      chip.addEventListener('click', () => {
        document.querySelectorAll('.chip[data-filter]').forEach((c) => c.classList.remove('active'));
        chip.classList.add('active');
        state.activeFilter = chip.getAttribute('data-filter');
        renderDirectory();
      });
    });
  }

  function openRecordModal(record) {
    const dialog = el('record-modal');
    el('modal-title').textContent = record.fqdn;
    const body = el('modal-body');
    body.innerHTML = '';

    const meta = document.createElement('div');
    meta.className = 'modal-meta';

    const items = [
      ['Owner', `@${record.owner}`],
      ['Status', record.status === 'active' ? 'Active DNS' : record.status === 'suspended' ? 'Suspended' : 'Indexed (Staging)'],
      ['Record Types', record.recordTypes.join(', ')],
      ['Cloudflare Proxy', record.proxied ? 'Enabled' : 'Disabled']
    ];
    for (const [k, v] of items) {
      const box = document.createElement('div');
      const st = document.createElement('strong');
      st.textContent = k;
      const sp = document.createElement('span');
      sp.textContent = v;
      box.append(st, sp);
      meta.appendChild(box);
    }

    const desc = document.createElement('p');
    desc.textContent = record.description;
    desc.style.color = 'var(--text-muted)';

    const pre = document.createElement('pre');
    pre.className = 'code-block';
    const code = document.createElement('code');
    code.textContent = JSON.stringify(record.record, null, 2);
    pre.appendChild(code);

    const actions = document.createElement('div');
    actions.style.display = 'flex';
    actions.style.gap = '0.6rem';
    actions.style.flexWrap = 'wrap';

    if (state.config?.repository) {
      const { url, branch } = state.config.repository;
      const srcLink = document.createElement('a');
      srcLink.href = `${url}/blob/${branch}/registry/domains/${encodeURIComponent(record.subdomain)}.json`;
      srcLink.target = '_blank';
      srcLink.rel = 'noopener noreferrer';
      srcLink.className = 'btn btn-secondary btn-sm';
      srcLink.textContent = 'View JSON on GitHub';
      actions.appendChild(srcLink);
    }

    if (record.repo) {
      const repoLink = document.createElement('a');
      repoLink.href = record.repo;
      repoLink.target = '_blank';
      repoLink.rel = 'noopener noreferrer';
      repoLink.className = 'btn btn-ghost btn-sm';
      repoLink.textContent = 'Project Repository';
      actions.appendChild(repoLink);
    }

    body.append(meta, desc, pre, actions);
    dialog.showModal();
  }

  function setupModal() {
    const dialog = el('record-modal');
    el('modal-close').addEventListener('click', () => dialog.close());
    dialog.addEventListener('click', (e) => {
      if (e.target === dialog) dialog.close();
    });
  }

  function renderDocTab(tabKey) {
    document.querySelectorAll('.doc-tab').forEach((btn) => {
      const active = btn.getAttribute('data-doc') === tabKey;
      btn.classList.toggle('active', active);
      btn.setAttribute('aria-selected', String(active));
    });
    el('docs-panel').innerHTML = DOC_CONTENT[tabKey] || DOC_CONTENT.registration;
  }

  function setupDocs() {
    document.querySelectorAll('.doc-tab').forEach((btn) => {
      btn.addEventListener('click', () => renderDocTab(btn.getAttribute('data-doc')));
    });
    document.querySelectorAll('[data-doc-tab]').forEach((link) => {
      link.addEventListener('click', () => renderDocTab(link.getAttribute('data-doc-tab')));
    });
    renderDocTab('registration');
  }

  async function boot() {
    initTheme();
    setupHeroChecker();
    setupBuilder();
    setupDirectoryControls();
    setupModal();
    setupDocs();

    await loadConfigAndRegistry();
    renderDirectory();
    updateBuilder();
    loadPendingPRs();
  }

  document.addEventListener('DOMContentLoaded', boot);
})();
