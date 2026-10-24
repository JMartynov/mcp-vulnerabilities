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

  function init() {
    setupEventListeners();
    await loadReleaseHistory();
  }

  function setupEventListeners() {
    // Release dropdown selector
    if (el.filterToolsOnly) el.filterToolsOnly.addEventListener("change", (e) => { renderUpdatedServers(currentReleaseData.updated_servers || []); });

    el.releaseSelect.addEventListener("change", (e) => {
      loadReleasePayload(e.target.value);
    });

    // Tab Switching
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

  async function loadReleaseHistory() {
    try {
      const res = await fetch("data/updates/updates_history.json");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      releaseHistory = await res.json();

      if (releaseHistory.length === 0) {
        el.releaseSelect.innerHTML = '<option value="">No release history available</option>';
        return;
      }

      el.releaseSelect.innerHTML = releaseHistory.map((r, idx) => {
        const counts = r.summary_counts || {};
        const dateStr = r.timestamp_utc ? new Date(r.timestamp_utc).toLocaleDateString() : "";
        return `
          <option value="${escapeHtml(r.data_file || "latest_update.json")}" ${idx === 0 ? "selected" : ""}>
            v${escapeHtml(r.release_version)} (${dateStr}) — ${counts.new_mcp_servers || 0} updated servers, ${counts.new_advisories || 0} CVEs
          </option>
        `;
      }).join("");

      // Load initial selected release
      await loadReleasePayload(releaseHistory[0].data_file || "latest_update.json");
    } catch (err) {
      console.warn("Falling back to data/updates/latest_update.json:", err);
      el.releaseSelect.innerHTML = '<option value="latest_update.json">Latest Sync Update</option>';
      await loadReleasePayload("latest_update.json");
    }
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

  function renderUpdatedServers(servers) {
    if (servers.length === 0) {
      el.serversCount.textContent = `Showing 0 updated MCP servers`;
      el.serversContainer.innerHTML = `<div class="empty-state">No modified or newly tracked MCP servers in this release update.</div>`;
      return;
    }

    let serversToRender = servers;
    if (el.filterToolsOnly && el.filterToolsOnly.checked) {
      serversToRender = serversToRender.filter(s => s.versions?.[0]?.tools?.length > 0);
    }
    el.serversCount.textContent = `Showing ${serversToRender.length.toLocaleString()} updated MCP servers`;

    el.serversContainer.innerHTML = serversToRender.map((s) => {
      const riskClass = `risk-${(s.static_risk_tier || "low").toLowerCase()}`;
      const changeTypeClass = s.change_type === "PATCHED_VERSION" ? "badge-success" : "badge-danger";
      const changeTypeLabel = s.change_type === "PATCHED_VERSION" ? "🟢 Patched Release Available" : "🔴 New Security Vulnerability";

      const vulnStatusBadge = s.is_vulnerable
        ? `<span class="badge badge-danger">🔴 Vulnerable</span>`
        : `<span class="badge badge-success">🟢 Clean</span>`;

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

      return `
        <article class="server-card">
          <div class="server-card-header">
            <div>
              <h3 class="server-title">${escapeHtml(s.display_name || s.package_name)}</h3>
              <span class="server-pkg-name">${escapeHtml(s.package_name)}</span>
            </div>
            <div class="card-badges">
              <span class="badge ${changeTypeClass}">${escapeHtml(changeTypeLabel)}</span>
              <span class="badge badge-eco">${escapeHtml(s.ecosystem)}</span>
              <span class="badge ${riskClass}">Risk: ${escapeHtml(s.static_risk_tier || "LOW")}</span>
            </div>
          </div>

          <div class="server-status-row">
            ${vulnStatusBadge}
            ${safeVerBadge}
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
    el.modalServerTitle.textContent = server.display_name || server.package_name;
    el.modalServerPkg.textContent = server.purl || `pkg:${server.ecosystem}/${server.package_name}`;

    el.modalServerRisk.textContent = `Risk: ${server.static_risk_tier || "LOW"}`;
    el.modalServerRisk.className = `badge risk-${(server.static_risk_tier || "low").toLowerCase()}`;

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

    el.modalCanonicalHash.textContent = `hash: ${v.toolset_canonical_hash || "none"}`;
    const tools = v.tools || [];
    el.toolsCountLabel.textContent = String(tools.length);

    if (tools.length === 0) {
      el.modalToolsContainer.innerHTML = `<p class="empty-state">No extracted tool signatures for version ${escapeHtml(v.version)}.</p>`;
      return;
    }

    el.modalToolsContainer.innerHTML = tools.map((tool) => {
      const riskClass = `risk-${(tool.risk_tier || "low").toLowerCase()}`;
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
            <h5 class="tool-name">🔧 ${escapeHtml(tool.name)}</h5>
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
