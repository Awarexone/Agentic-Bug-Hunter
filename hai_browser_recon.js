// ============================================================
// HAI BROWSER RECON — Paste in DevTools Console on hackerone.com
// ============================================================
// This script intercepts Hai's GraphQL requests to map its API surface.
// Usage: Open any report page → DevTools → Console → Paste this

(function() {
  console.log('[HAI RECON] Starting intercept...');

  // Store captured requests
  window.__hai_recon = {
    requests: [],
    mutations: new Set(),
    queries: new Set(),
    endpoints: new Set(),
  };

  // Intercept fetch
  const originalFetch = window.fetch;
  window.fetch = async function(...args) {
    const [url, options] = args;
    const urlStr = typeof url === 'string' ? url : url?.url || '';

    // Capture GraphQL requests
    if (urlStr.includes('graphql') || urlStr.includes('hai') || urlStr.includes('llm') || urlStr.includes('copilot')) {
      let body = null;
      try {
        if (options?.body) {
          body = JSON.parse(options.body);
        }
      } catch(e) {}

      const entry = {
        url: urlStr,
        method: options?.method || 'GET',
        body: body,
        timestamp: new Date().toISOString(),
        operationName: body?.operationName || 'unknown',
      };

      window.__hai_recon.requests.push(entry);

      if (body?.operationName) {
        if (body.query?.includes('mutation')) {
          window.__hai_recon.mutations.add(body.operationName);
        } else {
          window.__hai_recon.queries.add(body.operationName);
        }
      }

      window.__hai_recon.endpoints.add(urlStr);

      console.log(`[HAI RECON] ${entry.method} ${entry.operationName}`, body?.variables || '');
    }

    const response = await originalFetch.apply(this, args);

    // Clone and log response for GraphQL/Hai calls
    if (urlStr.includes('graphql') || urlStr.includes('hai')) {
      const clone = response.clone();
      clone.json().then(data => {
        const lastReq = window.__hai_recon.requests[window.__hai_recon.requests.length - 1];
        if (lastReq) {
          lastReq.response = data;
          // Check for errors (potential auth issues = IDOR opportunity)
          if (data?.errors) {
            console.warn(`[HAI RECON] ERROR in ${lastReq.operationName}:`, data.errors);
          }
        }
      }).catch(() => {});
    }

    return response;
  };

  // Intercept XMLHttpRequest too
  const origOpen = XMLHttpRequest.prototype.open;
  const origSend = XMLHttpRequest.prototype.send;

  XMLHttpRequest.prototype.open = function(method, url) {
    this.__hai_url = url;
    this.__hai_method = method;
    return origOpen.apply(this, arguments);
  };

  XMLHttpRequest.prototype.send = function(body) {
    if (this.__hai_url && (this.__hai_url.includes('hai') || this.__hai_url.includes('graphql') || this.__hai_url.includes('llm'))) {
      console.log(`[HAI RECON] XHR ${this.__hai_method} ${this.__hai_url}`);
      window.__hai_recon.endpoints.add(this.__hai_url);
    }
    return origSend.apply(this, arguments);
  };

  // Helper: dump all captured data
  window.haiDump = function() {
    console.log('\n========== HAI RECON DUMP ==========');
    console.log('Mutations found:', [...window.__hai_recon.mutations]);
    console.log('Queries found:', [...window.__hai_recon.queries]);
    console.log('Endpoints:', [...window.__hai_recon.endpoints]);
    console.log('Total requests:', window.__hai_recon.requests.length);
    console.log('Full data:', JSON.stringify(window.__hai_recon, null, 2));
    console.log('====================================\n');

    // Copy to clipboard
    const dump = {
      mutations: [...window.__hai_recon.mutations],
      queries: [...window.__hai_recon.queries],
      endpoints: [...window.__hai_recon.endpoints],
      requests: window.__hai_recon.requests,
    };

    try {
      navigator.clipboard.writeText(JSON.stringify(dump, null, 2));
      console.log('[HAI RECON] Data copied to clipboard!');
    } catch(e) {
      console.log('[HAI RECON] Could not copy to clipboard. Use: copy(JSON.stringify(window.__hai_recon, null, 2))');
    }

    return dump;
  };

  // Helper: search JS bundles for Hai-related code
  window.haiSearchBundles = async function() {
    console.log('[HAI RECON] Searching JS bundles for Hai operations...');
    const scripts = document.querySelectorAll('script[src]');
    const keywords = ['LlmConversation', 'HaiChat', 'Copilot', 'DestroyLlm', 'CreateLlm', 'hai_', 'copilot_', 'llm_message', 'llm_conversation'];

    for (const script of scripts) {
      try {
        const resp = await fetch(script.src);
        const text = await resp.text();

        for (const kw of keywords) {
          if (text.includes(kw)) {
            // Find context around keyword
            const idx = text.indexOf(kw);
            const context = text.substring(Math.max(0, idx - 100), idx + 200);
            console.log(`[HAI RECON] Found "${kw}" in ${script.src.split('/').pop()}:`);
            console.log(`  ...${context}...`);
          }
        }
      } catch(e) {
        // CORS blocked, skip
      }
    }
  };

  // Helper: reveal hidden Hai UI elements
  window.haiRevealUI = function() {
    let revealed = 0;
    document.querySelectorAll('[class*="hidden"], [class*="invisible"], [style*="display: none"], [style*="visibility: hidden"]').forEach(el => {
      const text = el.textContent?.toLowerCase() || '';
      const cls = el.className?.toLowerCase() || '';
      if (text.includes('hai') || text.includes('copilot') || text.includes('llm') || text.includes('ai') ||
          cls.includes('hai') || cls.includes('copilot') || cls.includes('llm')) {
        el.style.display = 'block';
        el.style.visibility = 'visible';
        el.classList.remove('hidden', 'invisible');
        revealed++;
        console.log(`[HAI RECON] Revealed element:`, el);
      }
    });
    console.log(`[HAI RECON] Revealed ${revealed} hidden Hai elements`);
  };

  console.log('[HAI RECON] Intercept active. Commands:');
  console.log('  haiDump()          - Export all captured requests');
  console.log('  haiSearchBundles() - Search JS bundles for Hai code');
  console.log('  haiRevealUI()      - Reveal hidden Hai UI elements');
  console.log('  Now interact with Hai, then run haiDump()');
})();
