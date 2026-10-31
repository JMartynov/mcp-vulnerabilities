// What's New & Release Updates Feed Application

(function () {
  let releaseHistory = [];
  let currentReleaseData = null;
  let expandedToolServers = new Set();
  let activeTab = "servers"; // "servers" | "advisories"

  let currentInspectedServer = null;
  let currentInspectedVersion = null;

  const el = {
    releaseSelect: document.getElementById("release-select"),
    releaseTimestamp: document.getElementById("release-timestamp"),
    statServers: document.getElementById("stat-update-servers"),
    statAdvisories: document.getElementById("stat-update-advisories"),
    statVersions: document.getElementById("stat-update-versions"),

    tabServers: document.getElementById("tab-update-servers"),
    tabAdvisories: document.getElementById("tab-update-advisories"),
    viewServers: document.getElementById("update-servers-view"),
    viewAdvisories: document.getElementById("update-advisories-view"),

    serversCount: document.getElementById("update-servers-count"),
    serversContainer: document.getElementById("servers-container"),

    advisoriesCount: document.getElementById("update-advisories-count"),
    advisoriesContainer: document.getElementById("advisories-container"),

    // Server Modal Elements
    serverModal: document.getElementById("server-modal"),
    serverModalClose: document.getElementById("server-modal-close"),
    modalServerTitle: document.getElementById("modal-server-title"),
    modalServerPkg: document.getElementById("modal-server-pkg"),
    modalServerRisk: document.getElementById("modal-server-risk"),
    modalServerStatus: document.getElementById("modal-server-status"),
    modalServerEco: document.getElementById("modal-server-eco"),
    modalServerLicense: document.getElementById("modal-server-license"),
    modalServerAuthor: document.getElementById("modal-server-author"),
    modalServerRepo: document.getElementById("modal-server-repo"),
    modalServerHomepage: document.getElementById("modal-server-homepage"),
    modalSecurityComment: document.getElementById("modal-security-comment"),
    modalVersionPills: document.getElementById("modal-version-pills"),
    selectedVersionLabel: document.getElementById("selected-version-label"),
    selectedVersionBadge: document.getElementById("selected-version-badge"),
    selectedVersionVulnContainer: document.getElementById("selected-version-vuln-container"),
    modalCanonicalHash: document.getElementById("modal-canonical-hash"),
    toolsCountLabel: document.getElementById("tools-count-label"),
    modalToolsContainer: document.getElementById("modal-tools-container"),
    exporterPinnedVersion: document.getElementById("exporter-pinned-version"),
    exportToast: document.getElementById("export-toast"),
    filterToolsOnly: document.getElementById("filterToolsOnly"),
    exportPreview: document.getElementById("export-preview"),
    
    // Comparator Toolbar
    versionComparatorToolbar: document.getElementById("version-comparator-toolbar"),
    compareBaseSelect: document.getElementById("compare-base-select"),
    currentCompareVersion: document.getElementById("current-compare-version"),
    diffSummaryRow: document.getElementById("diff-summary-row"),

    // Filters
    changeTypeFilters: document.getElementById("change-type-filters"),
    countAll: document.getElementById("count-all"),
    countPatched: document.getElementById("count-patched"),
    countVuln: document.getElementById("count-vuln"),
    countNew: document.getElementById("count-new"),

    // Sparkline
    historicalSparkline: document.getElementById("historical-sparkline"),

    // Advisory Modal
    advisoryModal: document.getElementById("advisory-modal"),
    advisoryModalClose: document.getElementById("modal-close"),
    modalId: document.getElementById("modal-id"),
    modalSeverity: document.getElementById("modal-severity"),
    modalBody: document.getElementById("modal-body"),
    modalExternalLink: document.getElementById("modal-external-link"),
  };

  window.toggleToolsExpand = async function(serverName) {
    if (expandedToolServers.has(serverName)) {
      expandedToolServers.delete(serverName);
    } else {
      expandedToolServers.add(serverName);
    }
    renderUpdatedServers(currentReleaseData.updated_servers || []);
  };

  window.openInspectorModal = function(pkgName, toolName) {
    openServerModal(pkgName);
    setTimeout(() => {
      const toolHeader = Array.from(document.querySelectorAll(".tool-name")).find(el => el.textContent.includes(toolName));
      if (toolHeader) {
        toolHeader.scrollIntoView({ behavior: "smooth", block: "center" });
        toolHeader.closest(".tool-signature-card").style.backgroundColor = "rgba(59, 130, 246, 0.1)";
        setTimeout(() => toolHeader.closest(".tool-signature-card").style.backgroundColor = "", 2000);
      }
    }, 500);
  };

  async function init() {
    setupEventListeners();
    await loadReleaseHistory();
  }

  function setupEventListeners() {
    // Release dropdown selector
    if (el.filterToolsOnly) el.filterToolsOnly.addEventListener("change", (e) => { renderUpdatedServers(currentReleaseData.updated_servers || []); });

    if (el.changeTypeFilters) {
      el.changeTypeFilters.addEventListener("click", (e) => {
        const chip = e.target.closest(".chip");
        if (!chip) return;
        
        el.changeTypeFilters.querySelectorAll(".chip").forEach(c => c.classList.remove("active"));
        chip.classList.add("active");
        
        renderUpdatedServers(currentReleaseData?.updated_servers || []);
      });
    }

    el.releaseSelect.addEventListener("change", (e) => {
      loadReleasePayload(e.target.value);
    });

    // Tab Switching
    if (el.compareBaseSelect) {
    el.compareBaseSelect.addEventListener("change", () => {
      if (currentInspectedVersion) {
        selectVersion(currentInspectedVersion);
      }
    });
  }
  el.tabServers.addEventListener("click", () => switchTab("servers"));
    el.tabAdvisories.addEventListener("click", () => switchTab("advisories"));

    // Modal Close handlers
    el.serverModalClose.addEventListener("click", () => el.serverModal.close());
    el.serverModal.addEventListener("click", (e) => {
      if (e.target === el.serverModal) el.serverModal.close();
    });

    el.advisoryModalClose.addEventListener("click", () => el.advisoryModal.close());
    el.advisoryModal.addEventListener("click", (e) => {
      if (e.target === el.advisoryModal) el.advisoryModal.close();
    });

    // Exporter buttons
    document.querySelectorAll(".btn-export").forEach((btn) => {
      btn.addEventListener("click", () => exportConfig(btn.dataset.client));
    });
  }

  function switchTab(tab) {
    activeTab = tab;
    if (tab === "servers") {
      el.tabServers.classList.add("active");
      el.tabServers.setAttribute("aria-selected", "true");
      el.tabAdvisories.classList.remove("active");
      el.tabAdvisories.setAttribute("aria-selected", "false");
      el.viewServers.style.display = "block";
      el.viewAdvisories.style.display = "none";
    } else {
      el.tabAdvisories.classList.add("active");
      el.tabAdvisories.setAttribute("aria-selected", "true");
      el.tabServers.classList.remove("active");
      el.tabServers.setAttribute("aria-selected", "false");
      el.viewAdvisories.style.display = "block";
      el.viewServers.style.display = "none";
    }
  }

  function compareSemVer(vA, vB) {
    const pA = vA.replace(/^v/i, "").split('.').map(x => parseInt(x, 10) || 0);
    const pB = vB.replace(/^v/i, "").split('.').map(x => parseInt(x, 10) || 0);
    const maxLen = Math.max(pA.length, pB.length);
    for (let i = 0; i < maxLen; i++) {
      const partA = pA[i] || 0;
      const partB = pB[i] || 0;
      if (partA > partB) return 1;
      if (partA < partB) return -1;
    }
    return 0;
  }

  async function loadReleaseHistory() {
    try {
      const res = await fetch("data/updates/updates_history.json");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      let rawHistory = await res.json();

      if (rawHistory.length === 0) {
        el.releaseSelect.innerHTML = '<option value="">No release history available</option>';
        return;
      }
      
      // Sort strictly in descending SemVer order
      releaseHistory = rawHistory.sort((a, b) => compareSemVer(b.release_version, a.release_version));

      el.releaseSelect.innerHTML = releaseHistory.map((r, idx) => {
        const counts = r.summary_counts || {};
        const dateStr = r.timestamp_utc ? new Date(r.timestamp_utc).toLocaleDateString() : "";
        const srvCount = counts.new_mcp_servers || 0;
        const advCount = counts.new_advisories || 0;
        
        // If it's a delta update (new_mcp_servers/new_advisories > 0 but not thousands typically),
        // we can format with '+'. To be safe, if we determine it's the very first release 
        // (last in descending history), we just show the raw count.
        const srvText = idx === releaseHistory.length - 1 ? `${srvCount}` : `+${srvCount}`;
        const advText = idx === releaseHistory.length - 1 ? `${advCount}` : `+${advCount}`;
        
        return `
          <option value="${escapeHtml(r.data_file || "latest_update.json")}" ${idx === 0 ? "selected" : ""}>
            v${escapeHtml(r.release_version)} (${dateStr}) — ${srvText} servers, ${advText} CVEs
          </option>
        `;
      }).join("");
      
      renderSparkline(releaseHistory);

      // Load initial selected release
      await loadReleasePayload(releaseHistory[0].data_file || "latest_update.json");
    } catch (err) {
      console.warn("Falling back to data/updates/latest_update.json:", err);
      el.releaseSelect.innerHTML = '<option value="latest_update.json">Latest Sync Update</option>';
      await loadReleasePayload("latest_update.json");
    }
  }
  
  function renderSparkline(history) {
    if (!el.historicalSparkline || history.length < 2) return;
    
    el.historicalSparkline.setAttribute("viewBox", "0 0 1000 80");
    el.historicalSparkline.setAttribute("preserveAspectRatio", "none");
    
    // Reverse history to show chronological order (oldest to newest)
    const reversedHistory = [...history].slice(0, 10).reverse();
    
    const svgWidth = 1000;
    const svgHeight = 80;
    const padding = 10;
    
    // Extract points
    const pointsAdvisories = reversedHistory.map(r => r.summary_counts?.new_advisories || 0);
    const pointsServers = reversedHistory.map(r => r.summary_counts?.new_mcp_servers || 0);
    
    const maxVal = Math.max(...pointsAdvisories, ...pointsServers, 1);
    
    const xScale = (svgWidth - 2 * padding) / (reversedHistory.length - 1);
    const yScale = (val) => svgHeight - padding - (val / maxVal) * (svgHeight - 2 * padding);
    
    const getPolyline = (points, color, width) => {
      const coords = points.map((val, i) => `${padding + i * xScale},${yScale(val)}`).join(" ");
      return `<polyline points="${coords}" fill="none" stroke="${color}" stroke-width="${width}" stroke-linecap="round" stroke-linejoin="round"/>`;
    };
    
    // Create the SVG content
    let svgContent = '';
    
    // Advisories line (Critical color)
    svgContent += getPolyline(pointsAdvisories, "var(--critical-color)", 3);
    
    // Servers line (Accent color)
    svgContent += getPolyline(pointsServers, "var(--accent-color)", 2);
    
    // Add dots
    pointsAdvisories.forEach((val, i) => {
      svgContent += `<circle cx="${padding + i * xScale}" cy="${yScale(val)}" r="4" fill="var(--bg-color)" stroke="var(--critical-color)" stroke-width="2"/>`;
    });
    
    pointsServers.forEach((val, i) => {
      svgContent += `<circle cx="${padding + i * xScale}" cy="${yScale(val)}" r="3" fill="var(--bg-color)" stroke="var(--accent-color)" stroke-width="2"/>`;
    });
    
    el.historicalSparkline.innerHTML = svgContent;
  }

  async function loadReleasePayload(filename) {
    try {
      const targetPath = filename.startsWith("data/") ? filename : `data/updates/${filename}`;
      const res = await fetch(targetPath);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      currentReleaseData = await res.json();
      renderCurrentRelease();
    } catch (err) {
      console.error("Failed to load release updates payload:", err);
      el.serversContainer.innerHTML = `<div class="error-msg">Failed to load release payload (${escapeHtml(filename)}).</div>`;
    }
  }

  function renderCurrentRelease() {
    if (!currentReleaseData) return;
    const r = currentReleaseData;
    const counts = r.summary_counts || {};

    el.statServers.textContent = (counts.new_mcp_servers || 0).toLocaleString();
    el.statAdvisories.textContent = (counts.new_advisories || 0).toLocaleString();
    el.statVersions.textContent = (counts.updated_mcp_versions || 0).toLocaleString();

    if (r.timestamp_utc) {
      el.releaseTimestamp.textContent = `Sync Date: ${new Date(r.timestamp_utc).toUTCString()}`;
    }

    renderUpdatedServers(r.updated_servers || []);
    renderUpdatedAdvisories(r.updated_advisories || []);
  }

  function getServerCompositeRisk(server) {
    if (server.composite_risk_tier) {
      const tier = server.composite_risk_tier.toUpperCase();
      return tier === "MODERATE" ? "MEDIUM" : tier;
    }
    if (!server.is_vulnerable) return (server.static_risk_tier || "LOW").toUpperCase();
    let highest = "LOW";
    const severities = { "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "MODERATE": 2, "LOW": 1, "UNKNOWN": 0 };
    let currentScore = severities[(server.static_risk_tier || "LOW").toUpperCase()] || 0;

    if (server.highest_cve_severity) {
      const cveSev = server.highest_cve_severity.toUpperCase();
      const cveScore = severities[cveSev] || 0;
      if (cveScore > currentScore) {
        currentScore = cveScore;
        highest = cveSev === "MODERATE" ? "MEDIUM" : cveSev;
      }
    }

    (server.versions || []).forEach(v => {
      if (v.is_vulnerable && v.advisories) {
        v.advisories.forEach(adv => {
          let sev = "UNKNOWN";
          if (adv.database_specific?.severity) {
             sev = adv.database_specific.severity.toUpperCase();
          } else if (adv.affected?.[0]?.database_specific?.severity) {
             sev = adv.affected[0].database_specific.severity.toUpperCase();
          } else if (adv.severity) {
             sev = adv.severity.toUpperCase();
          }
          const score = severities[sev] || 0;
          if (score > currentScore) {
            currentScore = score;
            highest = sev === "MODERATE" ? "MEDIUM" : sev;
          }
        });
      }
    });
    
    return currentScore > severities[(server.static_risk_tier || "LOW").toUpperCase()] ? highest : (server.static_risk_tier || "LOW");
  }

  function renderUpdatedServers(servers) {
    if (el.changeTypeFilters) {
      const allCount = servers.length;
      const patchedCount = servers.filter(s => s.change_type === "PATCHED_VERSION").length;
      const vulnCount = servers.filter(s => s.change_type === "NEW_VULNERABILITY").length;
      const newCount = servers.filter(s => s.change_type === "NEW_SERVER").length;
      
      if (el.countAll) el.countAll.textContent = `(${allCount})`;
      if (el.countPatched) el.countPatched.textContent = `(${patchedCount})`;
      if (el.countVuln) el.countVuln.textContent = `(${vulnCount})`;
      if (el.countNew) el.countNew.textContent = `(${newCount})`;
    }

    let serversToRender = servers;
    
    if (el.changeTypeFilters) {
      const activeChip = el.changeTypeFilters.querySelector(".chip.active");
      if (activeChip && activeChip.dataset.filter !== "ALL") {
        serversToRender = serversToRender.filter(s => s.change_type === activeChip.dataset.filter);
      }
    }
    
    if (el.filterToolsOnly && el.filterToolsOnly.checked) {
      serversToRender = serversToRender.filter(s => s.versions?.[0]?.tools?.length > 0);
    }

    if (serversToRender.length === 0) {
      el.serversCount.textContent = `Showing 0 updated MCP servers`;
      el.serversContainer.innerHTML = `<div class="empty-state">No modified or newly tracked MCP servers match these filters.</div>`;
      return;
    }

    el.serversCount.textContent = `Showing ${serversToRender.length.toLocaleString()} updated MCP servers`;

    el.serversContainer.innerHTML = serversToRender.map((s) => {
      const compRisk = typeof getServerCompositeRisk === "function" ? getServerCompositeRisk(s) : (s.static_risk_tier || "low");
      const riskClass = `risk-${compRisk.toLowerCase()}`;
      
      let changeTypeClass = "badge-danger";
      let changeTypeLabel = "🔴 New Security Vulnerability";
      if (s.change_type === "PATCHED_VERSION") {
        changeTypeClass = "badge-success";
        changeTypeLabel = "🟢 Patched Release Available";
      } else if (s.change_type === "NEW_SERVER") {
        changeTypeClass = "badge-eco";
        changeTypeLabel = "🆕 Newly Tracked Server";
      }

      let vulnStatusBadge = "";
      if (s.change_type === "PATCHED_VERSION") {
         vulnStatusBadge = s.is_vulnerable
          ? `<span class="badge badge-danger">🔴 Vulnerable</span>`
          : `<span class="badge badge-success">🟢 Clean</span>`;
      } else if (!s.is_vulnerable) {
         vulnStatusBadge = `<span class="badge badge-success">🟢 Clean</span>`;
      }

      const safeVerBadge = s.recommended_safe_version
        ? `<span class="safe-rec-pill">Recommended: v${escapeHtml(s.recommended_safe_version)}</span>`
        : "";

      const tools = s.versions?.[0]?.tools || [];
      let toolsHtml = "";
      if (!tools || tools.length === 0) {
        toolsHtml = `
          <div class="tools-section">
            <div class="no-tools-badge">No static tools declared (Remote Endpoint / Gateway)</div>
          </div>
        `;
      } else {
        const isExpanded = expandedToolServers.has(s.package_name);
        const displayCount = isExpanded ? tools.length : Math.min(5, tools.length);
        
        let toolPillsHtml = tools.slice(0, displayCount)
          .map((t) => `<span class="tool-pill" title="Tool: ${escapeHtml(t.name)}" onclick="openInspectorModal('${escapeHtml(s.package_name)}', '${escapeHtml(t.name)}')">🔧 ${escapeHtml(t.name)}</span>`)
          .join("");
          
        let expandBtn = "";
        if (tools.length > 5) {
          if (isExpanded) {
            expandBtn = `<span class="tool-tag-more" role="button" tabindex="0" onclick="toggleToolsExpand('${escapeHtml(s.package_name)}')" onkeypress="if(event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggleToolsExpand('${escapeHtml(s.package_name)}'); }">Show less ▴</span>`;
          } else {
            expandBtn = `<span class="tool-more" role="button" tabindex="0" onclick="toggleToolsExpand('${escapeHtml(s.package_name)}')" onkeypress="if(event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggleToolsExpand('${escapeHtml(s.package_name)}'); }">+${tools.length - 5} more</span>`;
          }
        }
        
        toolsHtml = toolPillsHtml + expandBtn;
      }

      const title = s.display_name || s.package_name;
      const showPkgName = title !== s.package_name;

      const transportTag = s.transport === 'sse' ? '🌐 Remote SSE Gateway' : '🖥️ Local Stdio';
      let supplyChainBadge = "";
      if (s.is_unpublished || s.repo_http_status === 404 || s.archival_reason) {
          supplyChainBadge = `<span class="badge badge-danger">⚠️ Repo 404 / Archived</span>`;
      }
      
      let primitivesHtml = `<div class="primitives-tally">🔧 ${s.tools_count || 0} Tools • 📄 ${s.prompts_count || 0} Prompts • 📦 ${s.resources_count || 0} Resources</div>`;
      
      let envVarsHtml = "";
      if (s.required_env_vars && s.required_env_vars.length > 0) {
          envVarsHtml = `<div class="env-vars-tag">Required Secrets: ${s.required_env_vars.map(e => `<code>🔑 ${escapeHtml(e)}</code>`).join(", ")}</div>`;
      }
      
      let fpBadge = "";
      if (s.toolset_canonical_hash) {
          fpBadge = `<div class="fp-badge" role="button" tabindex="0" onkeydown="if(event.key==='Enter'||event.key===' '){event.preventDefault();this.click();}" style="cursor: pointer;" onclick="navigator.clipboard.writeText('${s.toolset_canonical_hash}'); const t = this.querySelector('.tooltip'); t.textContent = 'Copied!'; t.style.display = 'inline'; setTimeout(() => { t.textContent = 'Copy'; t.style.display = 'none'; }, 2000);">🔑 sha256:${s.toolset_canonical_hash.substring(0, 8)}...<span class="tooltip" style="display:none;">Copy</span></div>`;
      }

      return `
        <article class="server-card">
          <div class="server-card-header">
            <div>
              <h3 class="server-title">${escapeHtml(title)}</h3>
              ${showPkgName ? `<span class="server-pkg-name">${escapeHtml(s.package_name)}</span>` : ""}
            </div>
            <div class="card-badges">
              <span class="badge ${changeTypeClass}">${escapeHtml(changeTypeLabel)}</span>
              <span class="badge badge-eco">${escapeHtml(s.ecosystem)}</span>
              <span class="badge ${riskClass}">Risk: ${escapeHtml(compRisk)}</span>
              <span class="badge badge-transport">${escapeHtml(transportTag)}</span>
              ${supplyChainBadge}
              ${fpBadge}
            </div>
          </div>

          <div class="server-status-row">
            ${vulnStatusBadge}
            ${safeVerBadge}
            ${primitivesHtml}
            ${envVarsHtml}
          </div>

          <p class="server-desc">${escapeHtml(s.description || "No description provided.")}</p>

          <div class="server-security-comment">
            🛡️ ${escapeHtml(s.security_summary || "Automated capability security assessment applied.")}
          </div>

          <div class="server-tools-row">
            ${toolsHtml}
          </div>

          <div class="server-card-footer">
            <div class="card-links">
              ${s.repository_url ? `<a href="${escapeHtml(s.repository_url)}" target="_blank" rel="noopener" class="card-link">📁 Repo</a>` : ""}
              ${s.homepage_url ? `<a href="${escapeHtml(s.homepage_url)}" target="_blank" rel="noopener" class="card-link">🌐 Home</a>` : ""}
            </div>
            <button type="button" class="btn btn-inspect" data-pkg="${escapeHtml(s.package_name)}">
              🔍 Inspect Server & Versions
            </button>
          </div>
        </article>
      `;
    }).join("");

    el.serversContainer.querySelectorAll(".btn-inspect").forEach((btn) => {
      btn.addEventListener("click", () => {
        const found = servers.find((s) => s.package_name === btn.dataset.pkg);
        if (found) openServerModal(found);
      });
    });
  }

  function renderUpdatedAdvisories(advisories) {
    el.advisoriesCount.textContent = `Showing ${advisories.length.toLocaleString()} advisories`;
    if (advisories.length === 0) {
      el.advisoriesContainer.innerHTML = `<div class="empty-state">No advisories recorded for this release update.</div>`;
      return;
    }

    el.advisoriesContainer.innerHTML = advisories.map((adv) => {
      const sev = adv.database_specific?.severity || adv.affected?.[0]?.database_specific?.severity || "UNKNOWN";
      const sevClass = `risk-${sev.toLowerCase()}`;
      const pkgs = (adv.affected || []).map((a) => a.package?.name).filter(Boolean);

      return `
        <article class="advisory-card" data-id="${escapeHtml(adv.id)}">
          <div class="advisory-card-header">
            <div>
              <span class="badge ${sevClass}">${escapeHtml(sev)}</span>
              <span class="advisory-id">${escapeHtml(adv.id)}</span>
            </div>
          </div>
          <h4 class="advisory-summary">${escapeHtml(adv.summary || "No summary available.")}</h4>
          <div class="advisory-pkgs">
            <strong>Packages:</strong> ${pkgs.map((p) => `<code>${escapeHtml(p)}</code>`).join(", ") || "Unknown"}
          </div>
        </article>
      `;
    }).join("");

    el.advisoriesContainer.querySelectorAll(".advisory-card").forEach((card) => {
      card.addEventListener("click", () => {
        const found = advisories.find((a) => a.id === card.dataset.id);
        if (found) openAdvisoryModal(found);
      });
    });
  }

  // Deep Dive Server Inspector Modal
  function openServerModal(server) {
    currentInspectedServer = server;
    const title = server.display_name || server.package_name;
    el.modalServerTitle.textContent = title;
    el.modalServerPkg.textContent = server.purl || `pkg:${server.ecosystem}/${server.package_name}`;

    const compRisk = getServerCompositeRisk(server);
    el.modalServerRisk.textContent = `Risk: ${compRisk}`;
    el.modalServerRisk.className = `badge risk-${compRisk.toLowerCase()}`;

    if (server.is_vulnerable) {
      el.modalServerStatus.textContent = "🔴 Contains Vulnerable Versions";
      el.modalServerStatus.className = "badge badge-danger";
    } else {
      el.modalServerStatus.textContent = "🟢 100% Clean Releases";
      el.modalServerStatus.className = "badge badge-success";
    }

    el.modalServerEco.textContent = `Ecosystem: ${server.ecosystem}`;
    el.modalServerLicense.textContent = `License: ${server.license || "None specified"}`;
    el.modalServerAuthor.textContent = `Author: ${server.author || "Unknown"}`;

    if (server.repository_url) {
      el.modalServerRepo.href = server.repository_url;
      el.modalServerRepo.style.display = "inline-flex";
    } else {
      el.modalServerRepo.style.display = "none";
    }

    if (server.homepage_url) {
      el.modalServerHomepage.href = server.homepage_url;
      el.modalServerHomepage.style.display = "inline-flex";
    } else {
      el.modalServerHomepage.style.display = "none";
    }

    el.modalSecurityComment.textContent = server.security_summary || "Automated capability and version security profile attached.";

    const versions = server.versions || [];
    if (versions.length === 0) {
      el.modalVersionPills.innerHTML = '<span class="empty-inline">No discrete version history available.</span>';
      selectVersion(null);
      return;
    }

    const defaultVer = server.recommended_safe_version
      ? versions.find((v) => v.version === server.recommended_safe_version) || versions[versions.length - 1]
      : versions[versions.length - 1];

    el.modalVersionPills.innerHTML = versions.map((v) => {
      const isVuln = v.is_vulnerable;
      const isRec = server.recommended_safe_version && v.version === server.recommended_safe_version;
      let badge = isVuln ? "🔴" : "🟢";
      let extra = isRec ? " (Recommended)" : "";
      return `
        <button type="button" class="version-pill ${isVuln ? "pill-vuln" : "pill-safe"} ${v === defaultVer ? "active" : ""}" data-ver="${escapeHtml(v.version)}">
          ${badge} v${escapeHtml(v.version)}${extra}
        </button>
      `;
    }).join("");

    el.modalVersionPills.querySelectorAll(".version-pill").forEach((btn) => {
      btn.addEventListener("click", () => {
        el.modalVersionPills.querySelectorAll(".version-pill").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        const found = versions.find((v) => v.version === btn.dataset.ver);
        selectVersion(found);
      });
    });

    selectVersion(defaultVer);

    const pinVer = server.recommended_safe_version || server.latest_version || "latest";
    el.exporterPinnedVersion.textContent = `v${pinVer}`;
    exportConfig("claude", true);

    el.serverModal.showModal();
  }


  function selectVersion(v) {
    // Setup comparator toolbar
    if (currentInspectedServer && currentInspectedServer.versions && currentInspectedServer.versions.length > 1) {
      el.versionComparatorToolbar.style.display = "flex";
      el.currentCompareVersion.textContent = v ? `v${v.version}` : "v...";
      
      // Preserve currently selected baseline if it's still valid
      let currentBase = el.compareBaseSelect.value;
      
      // Populate select
      let optionsHtml = '';
      let hasPrev = false;
      const allVers = [...currentInspectedServer.versions].reverse(); // newest first
      
      for (let i = 0; i < allVers.length; i++) {
        const ver = allVers[i];
        if (v && ver.version === v.version) {
          // If this is the currently selected target, the "previous" is i+1
          if (i + 1 < allVers.length) {
             optionsHtml = `<option value="prev">Previous Version (v${escapeHtml(allVers[i+1].version)})</option>` + optionsHtml;
             hasPrev = true;
          }
          continue; 
        }
        optionsHtml += `<option value="${escapeHtml(ver.version)}">v${escapeHtml(ver.version)}</option>`;
      }
      
      if (!hasPrev) {
         optionsHtml = `<option value="prev" disabled>No Previous Version</option>` + optionsHtml;
      }
      
      el.compareBaseSelect.innerHTML = optionsHtml;
      
      if (currentBase && Array.from(el.compareBaseSelect.options).some(o => o.value === currentBase)) {
        el.compareBaseSelect.value = currentBase;
      } else {
        el.compareBaseSelect.value = "prev";
      }
      
    } else {
      el.versionComparatorToolbar.style.display = "none";
    }

    // Reset sub-tabs to tools

    const toolsTabBtn = document.querySelector('.primitive-tab-btn:nth-child(1)');
    if (toolsTabBtn) {
        document.getElementById('modal-tools-container').style.display='block';
        const promptsContainer = document.getElementById('modal-prompts-container');
        if (promptsContainer) promptsContainer.style.display='none';
        const resourcesContainer = document.getElementById('modal-resources-container');
        if (resourcesContainer) resourcesContainer.style.display='none';
        const connsContainer = document.getElementById('modal-connections-container');
        if (connsContainer) connsContainer.style.display='none';
        document.querySelectorAll('.primitive-tab-btn').forEach(b => b.classList.remove('active'));
        toolsTabBtn.classList.add('active');
    }

    currentInspectedVersion = v;
    if (!v) {
      el.selectedVersionLabel.textContent = "N/A";
      el.selectedVersionBadge.textContent = "UNKNOWN";
      el.selectedVersionBadge.className = "badge";
      el.selectedVersionVulnContainer.innerHTML = '<p class="empty-state">No version data available.</p>';
      el.modalCanonicalHash.textContent = "hash: none";
      el.toolsCountLabel.textContent = "0";
      el.modalToolsContainer.innerHTML = "";
      return;
    }

    el.selectedVersionLabel.textContent = `v${v.version}`;
    if (v.is_vulnerable) {
      el.selectedVersionBadge.textContent = `🔴 VULNERABLE (${v.advisories?.length || 1} CVEs)`;
      el.selectedVersionBadge.className = "badge badge-danger";
    } else {
      el.selectedVersionBadge.textContent = "🟢 CLEAN / SAFE";
      el.selectedVersionBadge.className = "badge badge-success";
    }

    const advs = v.advisories || [];
    if (advs.length > 0) {
      el.selectedVersionVulnContainer.innerHTML = `
        <div class="version-vuln-matrix">
          ${advs.map((adv) => `
            <div class="vuln-matrix-item">
              <div class="vuln-matrix-header">
                <span class="badge badge-danger">${escapeHtml(adv.id || "CVE")}</span>
                <span class="badge risk-high">Severity: ${escapeHtml(adv.severity || "UNKNOWN")}</span>
                ${adv.cvss_score ? `<span class="badge">CVSS: ${escapeHtml(String(adv.cvss_score))}</span>` : ""}
                ${adv.owasp_mcp_category ? `<span class="badge badge-eco">${escapeHtml(adv.owasp_mcp_category)}</span>` : ""}
              </div>
              <p class="vuln-summary">${escapeHtml(adv.summary || "Security vulnerability affects this version release.")}</p>
              ${adv.vulnerable_tools && adv.vulnerable_tools.length > 0 ? `
                <div class="vuln-tools-tag-row">
                  <strong>Affected Tools:</strong>
                  ${adv.vulnerable_tools.map((t) => `<span class="tool-tag-danger">⚠️ ${escapeHtml(t)}</span>`).join("")}
                </div>
              ` : ""}
              ${adv.remediation_guidance ? `<div class="remediation-box">💡 <strong>Remediation:</strong> ${escapeHtml(adv.remediation_guidance)}</div>` : ""}
            </div>
          `).join("")}
        </div>
      `;
    } else {
      el.selectedVersionVulnContainer.innerHTML = `
        <div class="safe-release-banner">
          <span class="safe-icon">✅</span>
          <div>
            <strong>Clean Release:</strong>
            <p>Version <code>${escapeHtml(v.version)}</code> is not affected by any known OSV or CVE security advisories.</p>
          </div>
        </div>
      `;
    }

    // Toolset Delta Comparison
    const versions = currentInspectedServer?.versions || [];
    const vIndex = versions.findIndex(ver => ver.version === v.version);
    const prevVersion = vIndex < versions.length - 1 ? versions[vIndex + 1] : null;
    
    let fingerprintHtml = `<span class="verified-contract">🛡️ Verified Toolset Contract</span> <span style="cursor: pointer;" onclick="navigator.clipboard.writeText('${v.toolset_canonical_hash || ''}');">hash: ${v.toolset_canonical_hash || "none"}</span>`;
    
    const tools = v.tools || [];

    // Render diff summary if baseline is selected
    if (el.versionComparatorToolbar.style.display !== "none" && el.compareBaseSelect.value) {
      let baseVersionString = el.compareBaseSelect.value;
      if (baseVersionString === "prev") {
        const allVers = [...currentInspectedServer.versions].reverse();
        const idx = allVers.findIndex(ver => ver.version === v.version);
        if (idx >= 0 && idx + 1 < allVers.length) {
          baseVersionString = allVers[idx + 1].version;
        } else {
          baseVersionString = null;
        }
      }

      if (baseVersionString) {
        const baseV = currentInspectedServer.versions.find(x => x.version === baseVersionString);
        if (baseV) {
          let addedTools = 0;
          let removedTools = 0;
          let modParams = 0;
          let fixedCves = 0;
          let newCves = 0;
          let baseHash = baseV.toolset_canonical_hash || "none";
          let targetHash = v.toolset_canonical_hash || "none";
          
          const targetTools = v.tools || [];
          const baseTools = baseV.tools || [];
          
          const targetToolNames = new Set(targetTools.map(t => t.name));
          const baseToolNames = new Set(baseTools.map(t => t.name));
          
          targetTools.forEach(t => {
            if (!baseToolNames.has(t.name)) {
              addedTools++;
            } else {
              const bTool = baseTools.find(bt => bt.name === t.name);
              if (bTool) {
                const tParams = JSON.stringify(t.parameters || []);
                const bParams = JSON.stringify(bTool.parameters || []);
                if (tParams !== bParams) modParams++;
              }
            }
          });
          
          baseTools.forEach(t => {
            if (!targetToolNames.has(t.name)) removedTools++;
          });
          
          const targetCves = new Set((v.advisories || []).map(a => a.id));
          const baseCves = new Set((baseV.advisories || []).map(a => a.id));
          
          baseCves.forEach(c => {
            if (!targetCves.has(c)) fixedCves++;
          });
          
          targetCves.forEach(c => {
            if (!baseCves.has(c)) newCves++;
          });
          
          el.diffSummaryRow.innerHTML = `
            <div class="diff-pills">
              <span class="diff-pill diff-added">+ ${addedTools} Added Tools</span>
              <span class="diff-pill diff-removed">- ${removedTools} Removed Tools</span>
              <span class="diff-pill diff-modified">Δ ${modParams} Modified Parameters</span>
              <span class="diff-pill diff-fixed">🛡️ ${fixedCves} Fixed Vulnerabilities</span>
              ${newCves > 0 ? `<span class="diff-pill diff-newcve">🔴 ${newCves} New CVEs</span>` : ''}
            </div>
            <div class="diff-hash">
              <span class="hash-trans">${baseHash.replace('sha256:', '')} ➔ ${targetHash.replace('sha256:', '')}</span>
            </div>
          `;
          el.diffSummaryRow.style.display = "flex";
        } else {
          el.diffSummaryRow.style.display = "none";
        }
      } else {
        el.diffSummaryRow.style.display = "none";
      }
    } else {
      el.diffSummaryRow.style.display = "none";
    }
    const prevTools = prevVersion?.tools || [];
    
    const toolNames = new Set(tools.map(t => t.name));
    const prevToolNames = new Set(prevTools.map(t => t.name));
    
    const addedTools = [...toolNames].filter(name => !prevToolNames.has(name));
    const removedTools = [...prevToolNames].filter(name => !toolNames.has(name));
    
    if (prevVersion && prevVersion.toolset_canonical_hash !== v.toolset_canonical_hash) {
      fingerprintHtml = `<span class="verified-contract">🛡️ Verified Toolset Contract</span> <span style="opacity: 0.6; text-decoration: line-through;">sha256:${prevVersion.toolset_canonical_hash?.substring(0, 8) || "none"}...</span> ➔ sha256:${v.toolset_canonical_hash?.substring(0, 8) || "none"}...`;
    }
    
    el.modalCanonicalHash.innerHTML = fingerprintHtml;
    el.toolsCountLabel.textContent = String(tools.length);
    
    // Prompts
    const prompts = v.prompts || [];
    const promptsTab = document.getElementById("modal-prompts-container");
    if (promptsTab) {
        document.getElementById("prompts-count-label").textContent = String(prompts.length);
        if (prompts.length === 0) {
            promptsTab.innerHTML = `<p class="empty-state">No extracted prompt signatures for version ${escapeHtml(v.version)}.</p>`;
        } else {
            promptsTab.innerHTML = prompts.map(p => {
                const argsHtml = (p.arguments || []).map(a => `<tr><td><code>${escapeHtml(a.name)}</code></td><td>${a.required ? 'Yes' : 'No'}</td><td>${escapeHtml(a.description || '-')}</td></tr>`).join("");
                return `
                <div class="tool-signature-card">
                  <h5 class="tool-name">📄 ${escapeHtml(p.name)}</h5>
                  <p class="tool-desc">${escapeHtml(p.description || "No description.")}</p>
                  ${argsHtml ? `<table class="params-table"><thead><tr><th>Arg</th><th>Required</th><th>Description</th></tr></thead><tbody>${argsHtml}</tbody></table>` : ""}
                </div>`;
            }).join("");
        }
    }
    
    // Resources
    const resources = v.resources || [];
    const resourcesTab = document.getElementById("modal-resources-container");
    if (resourcesTab) {
        document.getElementById("resources-count-label").textContent = String(resources.length);
        if (resources.length === 0) {
            resourcesTab.innerHTML = `<p class="empty-state">No extracted resource signatures for version ${escapeHtml(v.version)}.</p>`;
        } else {
            resourcesTab.innerHTML = resources.map(r => `
                <div class="tool-signature-card">
                  <h5 class="tool-name">📦 ${escapeHtml(r.name)}</h5>
                  <p class="tool-desc">${escapeHtml(r.description || "No description.")}</p>
                  <p><strong>URI Template:</strong> <code>${escapeHtml(r.uriTemplate)}</code></p>
                </div>
            `).join("");
        }
    }
    
    // Env vars display inside modal
    const modalEnvContainer = document.getElementById("modal-env-vars-container");
    if (modalEnvContainer) {
        if (v.required_env_vars && v.required_env_vars.length > 0) {
            modalEnvContainer.innerHTML = `<strong>Required Environment Variables:</strong> ` + v.required_env_vars.map(e => `<code>🔑 ${escapeHtml(e)}</code>`).join(", ");
            modalEnvContainer.style.display = "block";
        } else {
            modalEnvContainer.style.display = "none";
        }
    }

    let deltaHtml = "";
    if (addedTools.length > 0 || removedTools.length > 0) {
      deltaHtml = `<div class="toolset-delta-box" style="margin-bottom: 20px; padding: 12px; background: var(--surface-hover); border-radius: var(--radius-sm); border: 1px solid var(--border-color);">
        <h5 style="margin-bottom: 8px; font-size: 0.85rem; color: var(--text-secondary);">Toolset Changes vs v${escapeHtml(prevVersion?.version || "")}</h5>
        <div style="display: flex; flex-wrap: wrap; gap: 8px;">
          ${addedTools.map(t => `<span style="color: var(--low-color); background: var(--low-bg); padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; border: 1px solid rgba(16, 185, 129, 0.3);">+ ${escapeHtml(t)}</span>`).join("")}
          ${removedTools.map(t => `<span style="color: var(--critical-color); background: var(--critical-bg); padding: 4px 8px; border-radius: 4px; font-size: 0.8rem; border: 1px solid rgba(239, 68, 68, 0.3);">- ${escapeHtml(t)}</span>`).join("")}
        </div>
      </div>`;
    }


    // Connections / Endpoints & Schema
    const connections = (v && v.connections && v.connections.length > 0) ? v.connections : ((currentInspectedServer && currentInspectedServer.connections && currentInspectedServer.connections.length > 0) ? currentInspectedServer.connections : []);
    
    const connsCountLabel = document.getElementById('connections-count-label');
    if (connsCountLabel) connsCountLabel.textContent = String(connections.length);
    
    const connsContainer = document.getElementById('modal-connections-container');
    if (connsContainer) {
      if (connections.length === 0) {
        connsContainer.innerHTML = '<div class="connection-card"><div class="connection-header"><span class="badge badge-info">🖥️ Process Transport (stdio)</span></div><p class="connection-desc">This server operates via standard input/output (stdio) process execution.</p></div>';
      } else {
        connsContainer.innerHTML = connections.map(conn => {
          let html = '<div class="connection-card">';
          html += `<div class="connection-header"><span class="badge badge-info">🔗 ${escapeHtml(conn.type || 'stdio')}</span></div>`;
          
          if (conn.deploymentUrl) {
            const safeUrlStr = conn.deploymentUrl.replace(/'/g, "\\'");
            html += `<div class="connection-url-box">
              <code>${escapeHtml(conn.deploymentUrl)}</code>
              <button class="btn btn-sm" onclick="navigator.clipboard.writeText('${safeUrlStr}')">Copy</button>
            </div>`;
            if (conn.deploymentUrl.startsWith('http://')) {
              html += '<div class="unencrypted-transport-warning">⚠️ Unencrypted HTTP Transport: Risk of credential and prompt interception in transit.</div>';
            }
          }
          
          const authType = conn.auth || conn.authentication || conn.authType;
          if (authType) {
            html += `<div class="connection-auth-badge"><span class="badge badge-warning">🔒 Auth: ${escapeHtml(authType)}</span></div>`;
          }
          
          if (conn.configSchema && conn.configSchema.properties) {
            const reqKeys = conn.configSchema.required || [];
            html += `<table class="config-params-table">
              <thead><tr><th>Parameter</th><th>Type</th><th>Required</th><th>Description</th></tr></thead>
              <tbody>`;
            
            for (const [key, prop] of Object.entries(conn.configSchema.properties)) {
              const isReq = reqKeys.includes(key);
              html += `<tr>
                <td><code>${escapeHtml(key)}</code></td>
                <td>${escapeHtml(prop.type || 'string')}</td>
                <td>${isReq ? 'Yes' : 'No'}</td>
                <td>${escapeHtml(prop.description || '-')}</td>
              </tr>`;
            }
            
            html += `</tbody></table>`;
          }
          
          html += '</div>';
          return html;
        }).join("");
      }
    }

    if (tools.length === 0 && removedTools.length === 0) {
      el.modalToolsContainer.innerHTML = `<p class="empty-state">No extracted tool signatures for version ${escapeHtml(v.version)}.</p>`;
      return;
    }

    let toolsHtml = "";
    
    if (tools.length > 0) {
      toolsHtml = tools.map((tool) => {
        const riskClass = `risk-${(tool.risk_tier || "low").toLowerCase()}`;
        const isNew = addedTools.includes(tool.name);
        const namePrefix = isNew ? `<span style="color: var(--low-color); margin-right: 6px;">[NEW]</span>` : "";
        const params = tool.parameters || [];

        const paramTableRows = params.map((p) => `
          <tr>
            <td><code>${escapeHtml(p.name || "")}</code></td>
            <td><span class="param-type">${escapeHtml(p.type || "string")}</span></td>
            <td>${p.required ? '<span class="param-req">Yes</span>' : '<span class="param-opt">No</span>'}</td>
            <td><code>${escapeHtml(p.default !== null && p.default !== undefined ? JSON.stringify(p.default) : "-")}</code></td>
            <td>${p.enum ? `<code>${escapeHtml(JSON.stringify(p.enum))}</code>` : "-"}</td>
            <td>${escapeHtml(p.description || "-")}</td>
          </tr>
        `).join("");

        return `
          <div class="tool-signature-card">
            <div class="tool-card-top">
              <h5 class="tool-name">${namePrefix}🔧 ${escapeHtml(tool.name)}</h5>
              <span class="badge ${riskClass}">Risk: ${escapeHtml(tool.risk_tier || "LOW")} (${tool.risk_score || 0})</span>
            </div>

            <p class="tool-desc">${escapeHtml(tool.description || "No tool description available.")}</p>

            ${tool.security_comment ? `
              <div class="tool-security-comment">
                🛡️ <strong>Tool Assessment:</strong> ${escapeHtml(tool.security_comment)}
              </div>
            ` : ""}

            <div class="tool-parameters-table-wrap">
              <table class="params-table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Required</th>
                    <th>Default</th>
                    <th>Enum</th>
                    <th>Description</th>
                  </tr>
                </thead>
                <tbody>
                  ${paramTableRows.length > 0 ? paramTableRows : '<tr><td colspan="6" class="text-center">No parameters required.</td></tr>'}
                </tbody>
              </table>
            </div>
          </div>
        `;
      }).join("");
    }
    
    el.modalToolsContainer.innerHTML = deltaHtml + toolsHtml;

  }

  function exportConfig(client, previewOnly = false) {
    if (!currentInspectedServer) return;
    const server = currentInspectedServer;
    const pinVer = server.recommended_safe_version || server.latest_version || "latest";
    const name = server.package_name;
    const eco = (server.ecosystem || "").toLowerCase();

    let cmd = name;
    let args = [];

    if (eco === "npm") {
      cmd = "npx";
      args = ["-y", `${name}@${pinVer}`];
    } else if (eco === "pypi") {
      cmd = "uvx";
      args = [`${name}==${pinVer}`];
    } else {
      cmd = name;
      args = [];
    }

    let configObj = {};
    if (client === "claude" || client === "cursor" || client === "windsurf") {
      configObj = {
        mcpServers: {
          [name]: {
            command: cmd,
            args: args,
          },
        },
      };
    } else if (client === "cline") {
      configObj = {
        mcpServers: {
          [name]: {
            command: cmd,
            args: args,
            disabled: false,
            autoApprove: [],
          },
        },
      };
    } else if (client === "zed") {
      configObj = {
        context_servers: [name],
      };
    }

    const jsonStr = JSON.stringify(configObj, null, 2);
    el.exportPreview.textContent = jsonStr;

    if (!previewOnly) {
      navigator.clipboard.writeText(jsonStr).then(() => {
        el.exportToast.style.display = "block";
        setTimeout(() => {
          el.exportToast.style.display = "none";
        }, 2500);
      }).catch((e) => console.warn("Clipboard write failed:", e));
    }
  }

  function openAdvisoryModal(adv) {
    el.modalId.textContent = adv.id;
    const sev = adv.database_specific?.severity || "UNKNOWN";
    el.modalSeverity.textContent = sev;
    el.modalSeverity.className = `badge risk-${sev.toLowerCase()}`;
    el.modalBody.innerHTML = `
      <p><strong>Summary:</strong> ${escapeHtml(adv.summary || "")}</p>
      <p><strong>Details:</strong></p>
      <pre class="advisory-details-pre"><code>${escapeHtml(adv.details || "No details.")}</code></pre>
    `;
    el.modalExternalLink.href = `https://osv.dev/vulnerability/${adv.id}`;
    el.advisoryModal.showModal();
  }

  function escapeHtml(str) {
    if (str === null || str === undefined) return "";
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  init();
})();

  window.detectCollisions = function() {
    const banner = document.getElementById("collisionWarning");
    if (!banner) return;
    
    const toolMap = {};
    
    Array.from(selectedServers).forEach(pkgName => {
      let server = null;
      if (window.updatesData && window.updatesData.new_servers) {
        server = window.updatesData.new_servers.find(s => s.package_name === pkgName);
      }
      
      if (server && server.tools_sample) {
        server.tools_sample.forEach(tool => {
          if (!toolMap[tool]) {
            toolMap[tool] = [];
          }
          toolMap[tool].push(pkgName);
        });
      }
    });
    
    const collisions = Object.entries(toolMap).filter(([tool, servers]) => servers.length > 1);
    
    if (collisions.length > 0) {
      let html = `<strong>⚠️ Cross-Server Tool Collision Detected</strong><br>The following tools are exported by multiple selected servers, which may cause runtime conflicts:<ul>`;
      collisions.forEach(([tool, servers]) => {
        html += `<li><code>${escapeHtml(tool)}</code> (in ${servers.map(escapeHtml).join(', ')})</li>`;
      });
      html += `</ul>`;
      
      banner.innerHTML = html;
      banner.style.display = "block";
    } else {
      banner.style.display = "none";
    }
  };


if ("serviceWorker" in navigator && (window.location.protocol === "https:" || window.location.hostname === "localhost")) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").then((reg) => {
      console.debug("[SW] Registered with scope:", reg.scope);
    }).catch((err) => {
      console.warn("[SW] Registration failed:", err);
    });
  });
}
