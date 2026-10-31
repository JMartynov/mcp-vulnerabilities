    // Escape HTML entities to prevent XSS (from memory rule)
    function escapeHtml(unsafe) {
      if (!unsafe) return "";
      return String(unsafe)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
    }

    async function loadAnalytics() {
      try {
        const response = await fetch('data/analytics.json');
        if (!response.ok) throw new Error('Failed to load analytics data');
        const data = await response.json();
        renderTopTools(data.top_tools);
        renderOwaspBreakdown(data.owasp_breakdown);
        renderEcosystems(data.ecosystems);
        renderZeroDayGap(data);
        renderCapabilities(data.capabilities);
        renderSecrets(data.top_secrets);
        renderShadowing(data.tool_shadowing);
        renderTransports(data.transports);
      } catch (err) {
        console.error(err);
        document.querySelectorAll('.loading-state').forEach(el => {
          el.textContent = 'Error loading analytics.';
        });
      }
    }

    function renderTopTools(tools) {
      const container = document.getElementById('chart-top-tools');
      container.innerHTML = '';
      
      if (!tools || tools.length === 0) {
        container.textContent = 'No data available.';
        return;
      }

      const maxCount = Math.max(...tools.map(t => t.count));

      tools.forEach(tool => {
        const pct = (tool.count / maxCount) * 100;
        const html = `
          <a href="index.html?q=${encodeURIComponent(tool.tool)}&status=vulnerable" class="chart-clickable-row" title="Drill down to affected servers in Directory">
            <div class="bar-chart-row">
              <div class="bar-label" title="${escapeHtml(tool.tool)}">${escapeHtml(tool.tool)} <span class="drilldown-icon">↗</span></div>
              <div class="bar-track">
                <div class="bar-fill" style="width: ${pct}%"></div>
              </div>
              <div class="bar-value">${tool.count}</div>
            </div>
            <div style="font-size: 0.75rem; text-align: right; margin-top: -10px; margin-bottom: 10px; color: #666;">
              Avg CVSS: ${tool.avg_cvss.toFixed(1)}
            </div>
          </a>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    function renderOwaspBreakdown(categories) {
      const container = document.getElementById('chart-owasp');
      container.innerHTML = '';
      
      if (!categories || categories.length === 0) {
        container.textContent = 'No data available.';
        return;
      }

      const maxCount = Math.max(...categories.map(c => c.count));

      categories.forEach(cat => {
        const pct = (cat.count / maxCount) * 100;
        
        // Find highest severity to color the bar
        let sevClass = '';
        if (cat.severities['CRITICAL']) sevClass = 'severity-critical';
        else if (cat.severities['HIGH']) sevClass = 'severity-high';
        else if (cat.severities['MEDIUM']) sevClass = 'severity-medium';

        const nameParts = cat.category.split(' - ');
        const displayName = nameParts.length > 1 ? nameParts[1] : cat.category;
        const tooltip = cat.category;

        const html = `
          <a href="index.html?q=${encodeURIComponent(displayName)}&status=vulnerable" class="chart-clickable-row" title="Drill down to affected servers in Directory">
            <div class="bar-chart-row">
              <div class="bar-label" title="${escapeHtml(tooltip)}">${escapeHtml(displayName)} <span class="drilldown-icon">↗</span></div>
              <div class="bar-track">
                <div class="bar-fill ${sevClass}" style="width: ${pct}%"></div>
              </div>
              <div class="bar-value">${cat.count} <span class="sub-value">(${cat.percentage.toFixed(1)}%)</span></div>
            </div>
          </a>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    function renderEcosystems(ecosystems) {
      const container = document.getElementById('chart-ecosystems');
      container.innerHTML = '';
      
      const entries = Object.entries(ecosystems || {}).map(([name, count]) => ({ name, count }));
      entries.sort((a, b) => b.count - a.count);

      if (entries.length === 0) {
        container.textContent = 'No data available.';
        return;
      }

      const maxCount = Math.max(...entries.map(e => e.count));

      entries.forEach(eco => {
        const pct = (eco.count / maxCount) * 100;
        const html = `
          <a href="index.html?eco=${encodeURIComponent(eco.name)}" class="chart-clickable-row" title="Drill down to affected servers in Directory">
            <div class="bar-chart-row">
              <div class="bar-label">${escapeHtml(eco.name)} <span class="drilldown-icon">↗</span></div>
              <div class="bar-track">
                <div class="bar-fill" style="width: ${pct}%; background: var(--badge-bg, #666);"></div>
              </div>
              <div class="bar-value">${eco.count}</div>
            </div>
          </a>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    function renderZeroDayGap(data) {
      const container = document.getElementById('chart-zero-day');
      container.innerHTML = '';
      
      if (data.patched_remediable_count === undefined) {
        container.textContent = 'No data available.';
        return;
      }

      const totalVuln = data.vulnerable_servers_count;
      const patched = data.patched_remediable_count;
      const unpatched = data.zero_day_unpatched_count;
      
      const pctPatched = totalVuln > 0 ? (patched / totalVuln * 100) : 0;
      const pctUnpatched = totalVuln > 0 ? (unpatched / totalVuln * 100) : 0;

      const html = `
        <a href="index.html?status=vulnerable&patch=available" class="chart-clickable-row" title="Drill down to affected servers in Directory">
          <div class="bar-chart-row">
            <div class="bar-label">Available Safe Patch <span class="drilldown-icon">↗</span></div>
            <div class="bar-track">
              <div class="bar-fill severity-medium" style="width: ${pctPatched}%"></div>
            </div>
            <div class="bar-value">${patched} <span class="sub-value">(${pctPatched.toFixed(1)}%)</span></div>
          </div>
        </a>
        <a href="index.html?status=vulnerable&patch=unpatched" class="chart-clickable-row" title="Drill down to affected servers in Directory">
          <div class="bar-chart-row">
            <div class="bar-label">NO KNOWN FIX (Zero-Day) <span class="drilldown-icon">↗</span></div>
            <div class="bar-track">
              <div class="bar-fill severity-critical" style="width: ${pctUnpatched}%"></div>
            </div>
            <div class="bar-value">${unpatched} <span class="sub-value">(${pctUnpatched.toFixed(1)}%)</span></div>
          </div>
        </a>
        <div style="font-size: 0.85rem; margin-top: 1rem; color: #666; background: #f9f9f9; padding: 0.75rem; border-radius: 4px; border-left: 3px solid #dc3545;">
          <strong>Guidance:</strong> ${unpatched} servers have active advisories but no upstream fix. Consider isolated sandboxing or removing these dependencies immediately.
        </div>
      `;
      container.innerHTML = html;
    }

    function renderCapabilities(caps) {
      const container = document.getElementById('chart-capabilities');
      container.innerHTML = '';
      if (!caps) return;
      
      // Use simple absolute values for bar lengths, scaling relative to max
      const vals = [caps.fs_read_write, caps.shell_exec, caps.network_egress, caps.mutating, caps.read_only];
      const maxCount = Math.max(...vals);
      
      const items = [
        { label: 'Filesystem Access', count: caps.fs_read_write },
        { label: 'Shell / Process Exec', count: caps.shell_exec, class: 'severity-critical' },
        { label: 'Network / Egress', count: caps.network_egress },
        { label: 'Mutating Capabilities', count: caps.mutating, class: 'severity-high' },
        { label: 'Read-Only Capabilities', count: caps.read_only, class: 'severity-medium' },
      ];
      
      items.forEach(item => {
        const pct = maxCount > 0 ? (item.count / maxCount * 100) : 0;
        const html = `
          <div class="bar-chart-row">
            <div class="bar-label">${escapeHtml(item.label)}</div>
            <div class="bar-track">
              <div class="bar-fill ${item.class || ''}" style="width: ${pct}%"></div>
            </div>
            <div class="bar-value">${item.count}</div>
          </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    function renderSecrets(secrets) {
      const container = document.getElementById('chart-secrets');
      container.innerHTML = '';
      if (!secrets || secrets.length === 0) {
        container.textContent = 'No secrets data available.';
        return;
      }
      const maxCount = Math.max(...secrets.map(s => s.count));
      secrets.forEach(sec => {
        const pct = (sec.count / maxCount) * 100;
        const html = `
          <div class="bar-chart-row">
            <div class="bar-label" style="font-family: monospace;">${escapeHtml(sec.name)}</div>
            <div class="bar-track">
              <div class="bar-fill severity-high" style="width: ${pct}%"></div>
            </div>
            <div class="bar-value">${sec.count}</div>
          </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    function renderShadowing(shadows) {
      const container = document.getElementById('chart-shadowing');
      container.innerHTML = '';
      if (!shadows || shadows.length === 0) {
        container.textContent = 'No shadowing data available.';
        return;
      }
      const maxCount = Math.max(...shadows.map(s => s.entropy));
      shadows.forEach(sh => {
        const pct = (sh.entropy / maxCount) * 100;
        const html = `
          <a href="index.html?q=${encodeURIComponent(sh.tool)}&sort=tools_desc" class="chart-clickable-row" title="Drill down to affected servers in Directory">
            <div class="bar-chart-row">
              <div class="bar-label" style="font-family: monospace;">${escapeHtml(sh.tool)} <span class="drilldown-icon">↗</span></div>
              <div class="bar-track">
                <div class="bar-fill severity-high" style="width: ${pct}%"></div>
              </div>
              <div class="bar-value">${sh.entropy} <span class="sub-value">hashes</span></div>
            </div>
          </a>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    function renderTransports(transports) {
      const container = document.getElementById('chart-transports');
      if (!container) return;
      const loader = document.getElementById('transport-loading');
      if (loader) loader.remove();
      
      if (!transports || Object.keys(transports).length === 0) {
        container.insertAdjacentHTML('beforeend', '<div>No data</div>');
        return;
      }
      const entries = Object.entries(transports).map(([name, count]) => ({ name, count }));
      entries.sort((a, b) => b.count - a.count);
      const maxCount = Math.max(...entries.map(e => e.count));
      const total = entries.reduce((sum, e) => sum + e.count, 0);
      
      entries.forEach(t => {
        const pct = (t.count / maxCount) * 100;
        const overallPct = (t.count / total) * 100;
        const html = `
          <div class="bar-chart-row" style="margin-bottom: 0.5rem;">
            <div class="bar-label" style="flex: 0 0 100px;">${escapeHtml(t.name)}</div>
            <div class="bar-track">
              <div class="bar-fill" style="width: ${pct}%; background: var(--badge-bg, #666);"></div>
            </div>
            <div class="bar-value" style="flex: 0 0 70px; font-size: 0.8rem;">${t.count} <span class="sub-value" style="margin-left: 0.1rem;">(${overallPct.toFixed(1)}%)</span></div>
          </div>
        `;
        container.insertAdjacentHTML('beforeend', html);
      });
    }

    document.addEventListener('DOMContentLoaded', loadAnalytics);


if ("serviceWorker" in navigator && (window.location.protocol === "https:" || window.location.hostname === "localhost")) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").then((reg) => {
      console.debug("[SW] Registered with scope:", reg.scope);
    }).catch((err) => {
      console.warn("[SW] Registration failed:", err);
    });
  });
}
