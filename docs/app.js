// MCP Security Vulnerability & Server Directory Explorer Application

(function () {
  // State
  let catalogIndex = [];
  let filteredServers = [];
  let allAdvisories = [];
  let filteredAdvisories = [];

  let activeTab = "directory"; // "directory" | "advisories" | "audit"

  // Directory Filters
  let activeVulnFilter = "ALL"; // "ALL" | "VULNERABLE" | "SAFE"
  let activeRiskFilter = "ALL"; // "ALL" | "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
  let activeDirectoryEco = "ALL";
  let directorySearchQuery = "";
  let expandedToolServers = new Set();

  // Advisory Filters
  let activeAdvisorySeverity = "ALL";
  let activeAdvisoryEco = "ALL";
  let advisorySearchQuery = "";

  // Shard Cache
  const shardCache = new Map();
  let currentInspectedServer = null;
  let currentInspectedVersion = null;

  // DOM Elements
  const el = {
    // Top Stats
    statTotalServers: document.getElementById("stat-total-servers"),
    statVulnServers: document.getElementById("stat-vuln-servers"),
    statSafeServers: document.getElementById("stat-safe-servers"),
    statTotalAdvisories: document.getElementById("stat-total-advisories"),

    // Tabs
    tabDirectory: document.getElementById("tab-directory"),
    tabAdvisories: document.getElementById("tab-advisories"),
    tabAudit: document.getElementById("tab-audit"),
    viewDirectory: document.getElementById("directory-view"),
    viewAdvisories: document.getElementById("advisories-view"),
    viewAudit: document.getElementById("audit-view"),

    // Audit Controls
    auditZone: document.getElementById("config-audit-zone"),
    auditFileInput: document.getElementById("audit-file-input"),
    auditResultsContainer: document.getElementById("audit-results-container"),
    auditTotalServers: document.getElementById("audit-total-servers"),
    auditSafeServers: document.getElementById("audit-safe-servers"),
    auditVulnServers: document.getElementById("audit-vuln-servers"),
    auditServerList: document.getElementById("audit-server-list"),
    auditRemediationPanel: document.getElementById("audit-remediation-panel"),
    auditBtnCopyRemediated: document.getElementById("btn-copy-remediated"),
    auditExportToast: document.getElementById("audit-export-toast"),
    auditExportPreview: document.getElementById("audit-export-preview"),

    // Directory Controls
    directorySearchInput: document.getElementById("directory-search-input"),
    vulnStatusChips: document.getElementById("vuln-status-chips"),
    riskTierChips: document.getElementById("risk-tier-chips"),
    directoryEcoChips: document.getElementById("directory-eco-chips"),
    directoryResultsCount: document.getElementById("directory-results-count"),
    serversContainer: document.getElementById("servers-container"),

    // Advisory Controls
    advisorySearchInput: document.getElementById("advisory-search-input"),
    advisorySeverityChips: document.getElementById("advisory-severity-chips"),
    advisoryEcoChips: document.getElementById("advisory-eco-chips"),
    filterToolsOnly: document.getElementById("filterToolsOnly"),
    advisoriesResultsCount: document.getElementById("advisories-results-count"),
    advisoriesContainer: document.getElementById("advisories-container"),

    // Server Deep-Dive Modal
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
    renderDirectoryCards();
  };

  async function init() {
    setupEventListeners();
    await Promise.all([loadCatalogIndex(), loadAdvisories()]);
    
    // Handle deep linking from URL query params
    const params = new URLSearchParams(window.location.search);
    const serverParam = params.get('server');
    const versionParam = params.get('version');
    
    if (serverParam) {
      // Find the server in the catalog
      const serverEntry = catalogIndex.find(s => s.package_name === serverParam || s.display_name === serverParam);
      if (serverEntry) {
        switchTab("directory");
        // Open modal
        await openServerModal(serverEntry.package_name, serverEntry.shard_file);
        
        // If version param provided, select it after modal opens
        if (versionParam && currentInspectedServer && currentInspectedServer.versions) {
          const targetVer = currentInspectedServer.versions.find(v => v.version === versionParam);
          if (targetVer) {
            // Update UI pills
            el.modalVersionPills.querySelectorAll(".version-pill").forEach((b) => b.classList.remove("active"));
            const pill = el.modalVersionPills.querySelector(`.version-pill[data-ver="${versionParam}"]`);
            if (pill) pill.classList.add("active");
            
            selectVersion(targetVer);
          }
        }
      }
    }
  }

  // Event Listeners
  function setupEventListeners() {
    // Tab Switching
    el.tabDirectory.addEventListener("click", () => switchTab("directory"));
    el.tabAdvisories.addEventListener("click", () => switchTab("advisories"));
    if (el.tabAudit) el.tabAudit.addEventListener("click", () => switchTab("audit"));

    // Audit Zone
    if (el.auditZone) {
      el.auditZone.addEventListener("dragover", (e) => {
        e.preventDefault();
        el.auditZone.classList.add("dragover");
      });
      el.auditZone.addEventListener("dragleave", () => {
        el.auditZone.classList.remove("dragover");
      });
      el.auditZone.addEventListener("drop", (e) => {
        e.preventDefault();
        el.auditZone.classList.remove("dragover");
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
          handleAuditFile(e.dataTransfer.files[0]);
        }
      });
      el.auditZone.addEventListener("click", () => {
        el.auditFileInput.click();
      });
      el.auditFileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
          handleAuditFile(e.target.files[0]);
        }
      });
      document.addEventListener("paste", (e) => {
        if (activeTab === "audit" && e.clipboardData) {
          const text = e.clipboardData.getData("text");
          if (text) handleAuditText(text);
        }
      });
    }

    if (el.auditBtnCopyRemediated) {
      el.auditBtnCopyRemediated.addEventListener("click", () => {
        const code = el.auditExportPreview.querySelector("code").textContent;
        navigator.clipboard.writeText(code).then(() => {
          el.auditExportToast.style.display = "block";
          setTimeout(() => {
            el.auditExportToast.style.display = "none";
          }, 2000);
        });
      });
    }

    // Directory Search & Filters
    el.directorySearchInput.addEventListener("input", (e) => {
      directorySearchQuery = e.target.value.trim().toLowerCase();
      applyDirectoryFilters();
    });

    el.vulnStatusChips.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      el.vulnStatusChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      activeVulnFilter = btn.dataset.vuln;
      applyDirectoryFilters();
    });

    el.riskTierChips.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      el.riskTierChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      activeRiskFilter = btn.dataset.risk;
      applyDirectoryFilters();
    });

    el.directoryEcoChips.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      el.directoryEcoChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      activeDirectoryEco = btn.dataset.eco;
      applyDirectoryFilters();
    });

    // Advisory Search & Filters
    el.filterToolsOnly.addEventListener("change", (e) => {
      applyDirectoryFilters();
      if (allAdvisories.length > 0) applyAdvisoryFilters();
    });

    el.advisorySearchInput.addEventListener("input", (e) => {
      advisorySearchQuery = e.target.value.trim().toLowerCase();
      applyAdvisoryFilters();
    });

    el.advisorySeverityChips.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      el.advisorySeverityChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      activeAdvisorySeverity = btn.dataset.severity;
      applyAdvisoryFilters();
    });

    el.advisoryEcoChips.addEventListener("click", (e) => {
      const btn = e.target.closest("button");
      if (!btn) return;
      el.advisoryEcoChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
      btn.classList.add("active");
      activeAdvisoryEco = btn.dataset.ecosystem;
      applyAdvisoryFilters();
    });

    // Modal Close buttons
    el.serverModalClose.addEventListener("click", () => el.serverModal.close());
    el.serverModal.addEventListener("click", (e) => {
      if (e.target === el.serverModal) el.serverModal.close();
    });

    el.advisoryModalClose.addEventListener("click", () => el.advisoryModal.close());
    el.advisoryModal.addEventListener("click", (e) => {
      if (e.target === el.advisoryModal) el.advisoryModal.close();
    });

    // Exporter Buttons
    document.querySelectorAll(".btn-export").forEach((btn) => {
      btn.addEventListener("click", () => exportConfig(btn.dataset.client));
    });
  }

  function switchTab(tab) {
    activeTab = tab;
    
    // Reset all
    [el.tabDirectory, el.tabAdvisories, el.tabAudit].forEach(t => {
      if(t) {
        t.classList.remove("active");
        t.setAttribute("aria-selected", "false");
      }
    });
    [el.viewDirectory, el.viewAdvisories, el.viewAudit].forEach(v => {
      if(v) v.style.display = "none";
    });

    if (tab === "directory") {
      el.tabDirectory.classList.add("active");
      el.tabDirectory.setAttribute("aria-selected", "true");
      el.viewDirectory.style.display = "block";
    } else if (tab === "advisories") {
      el.tabAdvisories.classList.add("active");
      el.tabAdvisories.setAttribute("aria-selected", "true");
      el.viewAdvisories.style.display = "block";
    } else if (tab === "audit") {
      if (el.tabAudit) {
        el.tabAudit.classList.add("active");
        el.tabAudit.setAttribute("aria-selected", "true");
      }
      if (el.viewAudit) el.viewAudit.style.display = "block";
    }
  }

  // Config Auditing Logic
  function handleAuditFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      handleAuditText(e.target.result);
    };
    reader.readAsText(file);
  }

  function stripComments(text) {
    // Strip /* */ comments
    let clean = text.replace(/\/\*[\s\S]*?\*\//g, '');
    
    // Process character by character for safer JSONC stripping
    let out = '';
    let inString = false;
    let i = 0;
    while(i < clean.length) {
      if(clean[i] === '"' && (i === 0 || clean[i-1] !== '\\')) {
        inString = !inString;
        out += clean[i];
        i++;
        continue;
      }
      if(!inString && clean[i] === '/' && clean[i+1] === '/') {
        while(i < clean.length && clean[i] !== '\n') i++;
        out += '\n';
        continue;
      }
      out += clean[i];
      i++;
    }
    // Remove trailing commas
    out = out.replace(/,\s*([\]}])/g, '$1');
    return out;
  }

  async function handleAuditText(text) {
    if (!allAdvisories || allAdvisories.length === 0) {
      await loadAdvisories();
    }
    
    let configObj = null;
    try {
      const cleanText = stripComments(text);
      configObj = JSON.parse(cleanText);
    } catch (e) {
      alert("Invalid JSON configuration pasted or dropped.");
      return;
    }

    if (!configObj) return;

    let serversObj = configObj.mcpServers || configObj.mcp_servers || configObj.context_servers || configObj.servers;
    
    // Check if root itself is a dictionary of server configs
    if (!serversObj && typeof configObj === 'object' && !Array.isArray(configObj)) {
        let isRoot = true;
        for (let k in configObj) {
            if (typeof configObj[k] !== 'object' || (!configObj[k].command && !configObj[k].args)) {
                isRoot = false;
                break;
            }
        }
        if (isRoot) serversObj = configObj;
    }

    if (!serversObj) {
      alert("No MCP servers found in the provided configuration.");
      return;
    }

    const auditResults = [];
    const remediatedServersObj = JSON.parse(JSON.stringify(serversObj));
    let remediated = false;

    for (const [name, conf] of Object.entries(serversObj)) {
      if (typeof conf !== "object") continue;
      
      let command = conf.command;
      let args = conf.args || [];
      if (typeof command === "object") {
         args = command.args || args;
         command = command.path || command.command;
      }

      if (!command) continue;

      const parsed = extractPackageInfo(command, args);
      
      let matchedServer = null;
      let isVuln = false;
      let safeVersion = null;
      let advisories = [];

      if (parsed && parsed.packageName) {
         matchedServer = catalogIndex.find(s => s.package_name === parsed.packageName || s.display_name === parsed.packageName);
      }

      if (matchedServer) {
         if (matchedServer.is_vulnerable) {
            isVuln = true;
            safeVersion = matchedServer.recommended_safe_version;
            
            if (parsed?.version && safeVersion && parsed.version === safeVersion) {
               isVuln = false;
            }

            if (isVuln) {
                advisories = findMatchingAdvisoriesForPackage(matchedServer?.package_name || parsed?.packageName, parsed?.version, safeVersion);
            }
            
            // Generate remediation diff if safe version exists
            if (safeVersion && isVuln) {
               remediated = true;
               remediatedServersObj[name] = generateRemediatedConfig(conf, parsed, safeVersion);
            }
         }
      }

      auditResults.push({
         name: name,
         command: [command, ...args].join(" "),
         parsedPackage: parsed ? parsed.packageName : "Unknown",
         parsedVersion: parsed ? parsed.version : "Unknown",
         isVulnerable: isVuln,
         matchedServer: matchedServer,
         safeVersion: safeVersion,
         advisories: advisories
      });
    }

    renderAuditResults(auditResults, configObj, remediatedServersObj, remediated);
  }

  function normalizePkgName(name) {
    return String(name || "").trim().toLowerCase().replace(/_/g, "-");
  }

  function findMatchingAdvisoriesForPackage(pkgName, pinnedVersion, safeVersion) {
    if (!pkgName || !Array.isArray(allAdvisories)) return [];
    const target = normalizePkgName(pkgName);
    const matched = [];

    for (const adv of allAdvisories) {
      const affectedList = Array.isArray(adv.affected) ? adv.affected : [];
      let pkgMatch = false;
      let dbSpec = adv.database_specific || {};

      for (const aff of affectedList) {
        const affName = normalizePkgName(aff.package?.name);
        if (affName && (affName === target || affName.endsWith("/" + target) || target.endsWith("/" + affName))) {
          pkgMatch = true;
          if (aff.database_specific) dbSpec = { ...dbSpec, ...aff.database_specific };
          break;
        }
      }
      if (!pkgMatch) continue;

      const cveAlias = Array.isArray(adv.aliases) ? adv.aliases.find((a) => String(a).startsWith("CVE-")) : null;
      const displayId = cveAlias && !String(adv.id).startsWith("CVE-") ? `${adv.id} (${cveAlias})` : (adv.id || "UNKNOWN-ADVISORY");
      const severity = String(dbSpec.severity || getSeverity(adv) || "HIGH").toUpperCase();
      const cvss = dbSpec.cvss_score !== undefined && dbSpec.cvss_score !== null ? Number(dbSpec.cvss_score) : null;

      matched.push({
        id: adv.id || "UNKNOWN",
        displayId,
        severity,
        cvssScore: !Number.isNaN(cvss) && cvss !== null ? cvss.toFixed(1) : null,
        summary: adv.summary || "Known MCP vulnerability affecting this package."
      });
    }
    return matched;
  }

  function extractPackageInfo(command, args) {
      let eco = "generic";
      let pkgName = null;
      let version = null;
      let p_args = Array.isArray(args) ? args.map(a => String(a)) : [];

      if (command.includes("npx") || command.includes("npm")) {
          eco = "npm";
          for (let arg of p_args) {
              if (arg.startsWith("-")) continue;
              if (arg === "npm" || arg === "npx" || arg === "run" || arg === "exec") continue;
              
              let parts = arg.split("@");
              if (arg.startsWith("@")) {
                 if (parts.length > 2) {
                     pkgName = "@" + parts[1];
                     version = parts[2];
                 } else {
                     pkgName = arg;
                 }
              } else {
                 pkgName = parts[0];
                 if (parts.length > 1) version = parts[1];
              }
              break;
          }
      } else if (command.includes("uvx") || command.includes("pipx") || command.includes("python")) {
          eco = "PyPI";
          let idx = 0;
          if (command.includes("python")) {
             while (idx < p_args.length && (p_args[idx] === "-m" || p_args[idx] === "pip" || p_args[idx].startsWith("-"))) {
                 idx++;
             }
          }
          if (idx < p_args.length) {
              let arg = p_args[idx];
              // Handle uvx syntax like pkg==1.0.0
              if (arg.includes("==")) {
                  let parts = arg.split("==");
                  pkgName = parts[0];
                  version = parts[1];
              } else if (arg.includes("@")) {
                  let parts = arg.split("@");
                  pkgName = parts[0];
                  version = parts[1];
              } else {
                  pkgName = arg;
              }
          }
      }

      if (!pkgName) return null;
      return { ecosystem: eco, packageName: pkgName, version: version };
  }

  function generateRemediatedConfig(originalConf, parsed, safeVersion) {
      const newConf = JSON.parse(JSON.stringify(originalConf));
      let args = Array.isArray(newConf.args) ? newConf.args : [];
      let command = newConf.command;
      
      let p_args = args.slice();
      let modified = false;

      if (parsed.ecosystem === "npm") {
          for (let i = 0; i < p_args.length; i++) {
              let arg = p_args[i];
              if (arg.startsWith("-")) continue;
              if (arg === "npm" || arg === "npx" || arg === "run" || arg === "exec") continue;
              
              p_args[i] = `${parsed.packageName}@${safeVersion}`;
              modified = true;
              break;
          }
      } else if (parsed.ecosystem === "PyPI") {
          let idx = 0;
          if (command.includes("python")) {
             while (idx < p_args.length && (p_args[idx] === "-m" || p_args[idx] === "pip" || p_args[idx].startsWith("-"))) {
                 idx++;
             }
          }
          if (idx < p_args.length) {
              let arg = p_args[idx];
              if (arg.includes("==")) {
                  p_args[idx] = `${parsed.packageName}==${safeVersion}`;
                  modified = true;
              } else if (arg.includes("@")) {
                  p_args[idx] = `${parsed.packageName}@${safeVersion}`;
                  modified = true;
              } else {
                  // Not pinned before, pin it now
                  if (command.includes("uvx") || command.includes("pipx")) {
                      p_args[idx] = `${parsed.packageName}@${safeVersion}`;
                  } else {
                      p_args[idx] = `${parsed.packageName}==${safeVersion}`;
                  }
                  modified = true;
              }
          }
      }

      if (modified) {
          newConf.args = p_args;
      }
      return newConf;
  }

  function renderAuditResults(results, originalConfig, remediatedServersObj, remediated) {
      el.auditZone.style.display = "none";
      el.auditResultsContainer.style.display = "block";

      let safeCount = 0;
      let vulnCount = 0;
      let advisoriesCount = 0;

      let listHtml = "";

      results.forEach(res => {
          if (res.isVulnerable) vulnCount++;
          else if (res.matchedServer) safeCount++;
          
          if (res.advisories) advisoriesCount += res.advisories.length;

          let statusClass = res.isVulnerable ? "vulnerable" : (res.matchedServer ? "clean" : "unknown");
          let statusBadge = "";
          let vulnInfo = "";

          if (res.isVulnerable) {
              statusBadge = `<span class="badge badge-danger">🔴 Vulnerable</span>`;
              
              let advListHtml = "";
              if (res.advisories && res.advisories.length > 0) {
                  advListHtml = `<div class="audit-cve-list">`;
                  res.advisories.forEach(adv => {
                      const sev = adv.severity || "UNKNOWN";
                      const sevClass = `risk-${sev.toLowerCase()}`;
                      const cvssText = adv.cvssScore ? `${sev} • CVSS ${adv.cvssScore}` : sev;
                      advListHtml += `
                          <div class="audit-cve-item">
                              <div class="cve-item-header">
                                  <span class="badge ${sevClass}">${escapeHtml(cvssText)}</span>
                                  <a href="https://osv.dev/vulnerability/${escapeHtml(adv.id)}" target="_blank" class="cve-id-link">${escapeHtml(adv.displayId)}</a>
                              </div>
                              <div class="cve-item-summary">${escapeHtml(adv.summary)}</div>
                          </div>
                      `;
                  });
                  advListHtml += `</div>`;
              }
              
              vulnInfo = `
                  <div class="audit-server-vuln-info">
                      <p><strong>⚠️ Security Risk Detected</strong></p>
                      <p>Found <strong>${escapeHtml(res.parsedPackage)}</strong> which has known vulnerabilities.</p>
                      ${advListHtml}
                      ${res.safeVersion ? `<p>Recommended Fix: Pin to <strong>v${escapeHtml(res.safeVersion)}</strong></p>` : `<p>No safe version known yet.</p>`}
                  </div>
              `;
          } else if (res.matchedServer) {
              statusBadge = `<span class="badge badge-success">🟢 Clean</span>`;
          } else {
              statusBadge = `<span class="badge">⚪ Unknown Package</span>`;
          }

          listHtml += `
              <div class="audit-server-item ${statusClass}">
                  <div class="audit-server-header">
                      <div>
                          <div class="audit-server-title">${escapeHtml(res.name)}</div>
                          <div class="audit-server-cmd">${escapeHtml(res.command)}</div>
                      </div>
                      ${statusBadge}
                  </div>
                  ${vulnInfo}
              </div>
          `;
      });

      el.auditTotalServers.textContent = results.length;
      el.auditSafeServers.textContent = safeCount;
      el.auditVulnServers.textContent = vulnCount;
      
      const elAdvisoriesStat = document.getElementById("audit-advisories-stat");
      const elAdvisoriesCount = document.getElementById("audit-advisories-count");
      if (elAdvisoriesStat && elAdvisoriesCount) {
          if (advisoriesCount > 0) {
              elAdvisoriesStat.style.display = "block";
              elAdvisoriesCount.textContent = advisoriesCount;
          } else {
              elAdvisoriesStat.style.display = "none";
          }
      }
      
      el.auditServerList.innerHTML = listHtml;

      if (remediated) {
          el.auditRemediationPanel.style.display = "block";
          
          let newConfigObj = JSON.parse(JSON.stringify(originalConfig));
          if (newConfigObj.mcpServers) newConfigObj.mcpServers = remediatedServersObj;
          else if (newConfigObj.mcp_servers) newConfigObj.mcp_servers = remediatedServersObj;
          else if (newConfigObj.context_servers) newConfigObj.context_servers = remediatedServersObj;
          else if (newConfigObj.servers) newConfigObj.servers = remediatedServersObj;
          else newConfigObj = remediatedServersObj;

          el.auditExportPreview.querySelector("code").textContent = JSON.stringify(newConfigObj, null, 2);
      } else {
          el.auditRemediationPanel.style.display = "none";
      }
  }

  // Load Data
  async function loadCatalogIndex() {
    try {
      const res = await fetch("data/mcp_catalog_index.json");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      catalogIndex = await res.json();
      updateTopMetrics();
      applyDirectoryFilters();
    } catch (err) {
      console.error("Failed to load mcp_catalog_index.json:", err);
      el.serversContainer.innerHTML = `<div class="error-msg">Failed to load server catalog index. Ensure <code>python -m mcp_vulnerabilities.site_builder</code> has run.</div>`;
    }
  }

  async function loadAdvisories() {
    try {
      const res = await fetch("data/vulnerabilities.json");
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      allAdvisories = await res.json();
      updateTopMetrics();
      applyAdvisoryFilters();
    } catch (err) {
      console.error("Failed to load vulnerabilities.json:", err);
    }
  }

  function updateTopMetrics() {
    if (catalogIndex.length > 0) {
      const total = catalogIndex.length;
      const vuln = catalogIndex.filter((s) => s.is_vulnerable).length;
      const safe = total - vuln;
      el.statTotalServers.textContent = total.toLocaleString();
      el.statVulnServers.textContent = vuln.toLocaleString();
      el.statSafeServers.textContent = safe.toLocaleString();
    }
    if (allAdvisories.length > 0) {
      el.statTotalAdvisories.textContent = allAdvisories.length.toLocaleString();
    }
  }

  // Directory Filters & Render
  function applyDirectoryFilters() {
    filteredServers = catalogIndex.filter((server) => {
      // Vulnerability filter
      if (activeVulnFilter === "VULNERABLE" && !server.is_vulnerable) return false;
      if (activeVulnFilter === "SAFE" && server.is_vulnerable) return false;

      // Risk Tier filter
      if (activeRiskFilter !== "ALL") {
        if (getServerCompositeRisk(server).toUpperCase() !== activeRiskFilter) return false;
      }

      // Ecosystem filter
      if (activeDirectoryEco !== "ALL") {
        if ((server.ecosystem || "").toLowerCase() !== activeDirectoryEco.toLowerCase()) return false;
      }

      // Has Tools Only Filter
      if (el.filterToolsOnly && el.filterToolsOnly.checked) {
        if (!server.tools_count || server.tools_count === 0) return false;
      }

      // Search Query
      if (directorySearchQuery) {
        const query = directorySearchQuery;
        const inName = (server.package_name || "").toLowerCase().includes(query);
        const inDisplay = (server.display_name || "").toLowerCase().includes(query);
        const inDesc = (server.description || "").toLowerCase().includes(query);
        const inAuthor = (server.author || "").toLowerCase().includes(query);
        const inTools = (server.tools_sample || []).some((t) => t.toLowerCase().includes(query));
        if (!inName && !inDisplay && !inDesc && !inAuthor && !inTools) return false;
      }

      return true;
    });

    el.directoryResultsCount.textContent = `Showing ${filteredServers.length.toLocaleString()} of ${catalogIndex.length.toLocaleString()} servers`;
    renderDirectoryCards();
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

  function renderDirectoryCards() {
    if (filteredServers.length === 0) {
      el.serversContainer.innerHTML = `<div class="empty-state">No MCP servers match the current filters.</div>`;
      return;
    }

    // Render first 100 for DOM performance with scroll
    const toRender = filteredServers.slice(0, 100);
    const html = toRender.map((s) => {
      const compRisk = getServerCompositeRisk(s);
      const riskClass = `risk-${compRisk.toLowerCase()}`;
      const vulnStatusBadge = s.is_vulnerable
        ? `<span class="badge badge-danger">🔴 ${s.vulnerable_versions_count || 1} Vulnerable Release${s.vulnerable_versions_count > 1 ? "s" : ""}</span>`
        : `<span class="badge badge-success">🟢 Clean Release</span>`;

      const safeVerBadge = s.recommended_safe_version
        ? `<span class="safe-rec-pill">Recommended: v${escapeHtml(s.recommended_safe_version)}</span>`
        : "";

      let toolsHtml = "";
      if (!s.tools_count || s.tools_count === 0) {
        toolsHtml = `
          <div class="tools-section">
            <div class="no-tools-badge">No static tools declared (Remote Endpoint / Gateway)</div>
          </div>
        `;
      } else {
        const isExpanded = expandedToolServers.has(s.package_name);
        const allTools = s.tools_sample || [];
        const displayCount = isExpanded ? allTools.length : Math.min(5, allTools.length);
        
        let toolPillsHtml = allTools.slice(0, displayCount)
          .map((t) => `<span class="tool-pill" title="Tool: ${escapeHtml(t)}" onclick="openInspectorModal('${escapeHtml(s.package_name)}', '${escapeHtml(t)}')">🔧 ${escapeHtml(t)}</span>`)
          .join("");
          
        let expandBtn = "";
        if (s.tools_count > 5) {
          if (isExpanded) {
            expandBtn = `<span class="tool-tag-more" role="button" tabindex="0" onclick="toggleToolsExpand('${escapeHtml(s.package_name)}')" onkeypress="if(event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggleToolsExpand('${escapeHtml(s.package_name)}'); }">Show less ▴</span>`;
          } else {
            expandBtn = `<span class="tool-more" role="button" tabindex="0" onclick="toggleToolsExpand('${escapeHtml(s.package_name)}')" onkeypress="if(event.key === 'Enter' || event.key === ' ') { event.preventDefault(); toggleToolsExpand('${escapeHtml(s.package_name)}'); }">+${s.tools_count - 5} more</span>`;
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
            <button type="button" class="btn btn-inspect" data-pkg="${escapeHtml(s.package_name)}" data-shard="${escapeHtml(s.shard_file || "")}">
              🔍 Inspect Server & Versions
            </button>
          </div>
        </article>
      `;
    }).join("");

    el.serversContainer.innerHTML = html;

    // Attach click handlers to Inspect buttons
    el.serversContainer.querySelectorAll(".btn-inspect").forEach((btn) => {
      btn.addEventListener("click", () => openServerModal(btn.dataset.pkg, btn.dataset.shard));
    });
  }

  // Deep-Dive Modal with On-Demand Sharding
  window.openInspectorModal = function(pkgName, toolName) {
    const s = catalogIndex.find(x => x.package_name === pkgName);
    openServerModal(pkgName, s ? s.shard_file : null);
    setTimeout(() => {
      const toolHeader = Array.from(document.querySelectorAll(".tool-name")).find(el => el.textContent.includes(toolName));
      if (toolHeader) {
        toolHeader.scrollIntoView({ behavior: "smooth", block: "center" });
        toolHeader.closest(".tool-signature-card").style.backgroundColor = "rgba(59, 130, 246, 0.1)";
        setTimeout(() => toolHeader.closest(".tool-signature-card").style.backgroundColor = "", 2000);
      }
    }, 500);
  };

  async function openServerModal(pkgName, shardFile) {
    el.modalServerTitle.textContent = "Loading server details...";
    el.modalServerPkg.textContent = pkgName;
    el.modalVersionPills.innerHTML = '<span class="loading-inline">Fetching shard data...</span>';
    el.serverModal.showModal();

    try {
      let shardData = shardCache.get(shardFile);
      if (!shardData && shardFile) {
        const res = await fetch(`data/shards/${shardFile}`);
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        shardData = await res.json();
        shardCache.set(shardFile, shardData);
      }

      const server = shardData ? shardData[pkgName] : null;
      if (!server) {
        throw new Error(`Package ${pkgName} not found in shard ${shardFile}`);
      }

      currentInspectedServer = server;
      renderServerModalDetails(server);
    } catch (err) {
      console.error("Failed to load shard details:", err);
      el.modalServerTitle.textContent = pkgName;
      el.modalVersionPills.innerHTML = `<div class="error-msg">Failed to load detailed shard for ${escapeHtml(pkgName)}.<br><br></div>`;
      const retryBtn = document.createElement("button");
      retryBtn.className = "btn btn-inspect";
      retryBtn.textContent = "Retry Fetch";
      retryBtn.onclick = () => openServerModal(pkgName, shardFile);
      el.modalVersionPills.querySelector(".error-msg").appendChild(retryBtn);
    }
  }

  function renderServerModalDetails(server) {
    const title = server.display_name || server.package_name;
    el.modalServerTitle.textContent = title;
    el.modalServerPkg.textContent = server.purl || `pkg:${server.ecosystem}/${server.package_name}`;

    // Risk tier & Status
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

    // Version Selector Pills
    const versions = server.versions || [];
    if (versions.length === 0) {
      el.modalVersionPills.innerHTML = '<span class="empty-inline">No discrete version history available.</span>';
      selectVersion(null);
      return;
    }

    // Default to recommended safe version or latest
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

    // Setup Exporter Pinned Version
    const pinVer = server.recommended_safe_version || server.latest_version || "latest";
    el.exporterPinnedVersion.textContent = `v${pinVer}`;
    exportConfig("claude", true); // preview only
  }

  function selectVersion(v) {
    // Reset sub-tabs to tools
    const toolsTabBtn = document.querySelector('.primitive-tab-btn:nth-child(1)');
    if (toolsTabBtn) {
        document.getElementById('modal-tools-container').style.display='block';
        const promptsContainer = document.getElementById('modal-prompts-container');
        if (promptsContainer) promptsContainer.style.display='none';
        const resourcesContainer = document.getElementById('modal-resources-container');
        if (resourcesContainer) resourcesContainer.style.display='none';
        document.querySelectorAll('.primitive-tab-btn').forEach(b => b.classList.remove('active'));
        toolsTabBtn.classList.add('active');
    }

    // Update URL query param for deep linking without reloading
    if (currentInspectedServer && v) {
      const url = new URL(window.location);
      url.searchParams.set('server', currentInspectedServer.package_name);
      url.searchParams.set('version', v.version);
      window.history.replaceState({}, '', url);
    } else if (!currentInspectedServer) {
      const url = new URL(window.location);
      url.searchParams.delete('server');
      url.searchParams.delete('version');
      window.history.replaceState({}, '', url);
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

    // Version Vulnerability Matrix
    const advs = v.advisories || [];
    
    // Remediation box logic
    let remediationHtml = "";
    if (v.is_vulnerable && currentInspectedServer) {
      const recVer = currentInspectedServer.recommended_safe_version;
      const eco = currentInspectedServer.ecosystem || "";
      const pkgName = currentInspectedServer.package_name || "";
      
      if (recVer) {
        let upgradeCmd = "";
        if (eco.toLowerCase() === "npm") {
          upgradeCmd = `npm install ${pkgName}@^${recVer}`;
        } else if (eco.toLowerCase() === "pypi") {
          upgradeCmd = `pip install ${pkgName}>=${recVer}`;
        } else {
          upgradeCmd = `Update ${pkgName} to v${recVer}`;
        }
        
        remediationHtml = `
          <div class="remediation-box">
            <strong>⚠️ Remediation: Update to version ${escapeHtml(recVer)} or higher to resolve this issue.</strong>
            <div class="remediation-command-wrap">
              <code id="remediation-cmd-text">${escapeHtml(upgradeCmd)}</code>
              <button class="btn-copy-cmd" id="btn-copy-remediation">Copy Command</button>
            </div>
          </div>
        `;
      } else {
        remediationHtml = `
          <div class="remediation-box">
            <strong>⚠️ No fixed version available upstream yet</strong>
            <p>Consider applying sandbox isolation rules or disabling affected tools.</p>
          </div>
        `;
      }
    }
    
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
                  ${adv.vulnerable_tools.map((t) => `<span class="tool-tag tool-tag-danger" onclick="openInspectorModal('${escapeHtml(currentInspectedServer.package_name)}', '${escapeHtml(t)}')">⚠️ ${escapeHtml(t)}</span>`).join("")}
                </div>
              ` : ""}
            </div>
          `).join("")}
        </div>
        ${remediationHtml}
      `;
      
      const copyBtn = document.getElementById("btn-copy-remediation");
      if (copyBtn) {
        copyBtn.addEventListener("click", () => {
          const cmdText = document.getElementById("remediation-cmd-text").textContent;
          navigator.clipboard.writeText(cmdText).then(() => {
            const originalText = copyBtn.textContent;
            copyBtn.textContent = "Copied!";
            copyBtn.style.backgroundColor = "#10b981";
            copyBtn.style.color = "#fff";
            setTimeout(() => {
              copyBtn.textContent = originalText;
              copyBtn.style.backgroundColor = "";
              copyBtn.style.color = "";
            }, 2000);
          });
        });
      }
      
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

    // Tools & Parameters Table
    el.modalCanonicalHash.innerHTML = `<span class="verified-contract">🛡️ Verified Toolset Contract</span> <span style="cursor: pointer;" onclick="navigator.clipboard.writeText('${v.toolset_canonical_hash || ''}');">hash: ${v.toolset_canonical_hash || "none"}</span>`;
    
    // Tools
    const tools = v.tools || [];
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

    if (tools.length === 0) {
      el.modalToolsContainer.innerHTML = `<p class="empty-state">No extracted tool signatures for version ${escapeHtml(v.version)}.</p>`;
      return;
    }

    el.modalToolsContainer.innerHTML = tools.map((tool) => {
      const riskClass = `risk-${(tool.risk_tier || "low").toLowerCase()}`;
      const params = tool.parameters || [];

      // Parameter Schema Table
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

  // Safe AI Client Config Exporter
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
    if (client === "claude") {
      configObj = {
        mcpServers: {
          [name]: {
            command: cmd,
            args: args,
          },
        },
      };
    } else if (client === "cursor") {
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
        context_servers: [
          name,
        ],
      };
    } else if (client === "windsurf") {
      configObj = {
        mcpServers: {
          [name]: {
            command: cmd,
            args: args,
          },
        },
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

  function advisoryHasVulnerableTools(adv) {
    if (Array.isArray(adv.database_specific?.vulnerable_tools) && adv.database_specific.vulnerable_tools.length > 0) {
      return true;
    }
    if (Array.isArray(adv.affected)) {
      return adv.affected.some(
        (aff) => Array.isArray(aff.database_specific?.vulnerable_tools) && aff.database_specific.vulnerable_tools.length > 0
      );
    }
    return false;
  }

  // Advisory Feed (Tab 2) Logic
  function applyAdvisoryFilters() {
    filteredAdvisories = allAdvisories.filter((adv) => {
      // Severity Filter
      if (activeAdvisorySeverity !== "ALL") {
        const sev = getSeverity(adv);
        if (sev !== activeAdvisorySeverity) return false;
      }

      // Ecosystem Filter
      if (activeAdvisoryEco !== "ALL") {
        const ecosystems = getEcosystems(adv);
        if (!ecosystems.includes(activeAdvisoryEco)) return false;
      }

      // Has Tools Only Filter
      if (el.filterToolsOnly && el.filterToolsOnly.checked) {
        if (!advisoryHasVulnerableTools(adv)) return false;
      }

      // Search Query
      if (advisorySearchQuery) {
        const q = advisorySearchQuery;
        const inId = (adv.id || "").toLowerCase().includes(q);
        const inSummary = (adv.summary || "").toLowerCase().includes(q);
        const inPkgs = getPackages(adv).some((p) => p.toLowerCase().includes(q));
        if (!inId && !inSummary && !inPkgs) return false;
      }

      return true;
    });

    el.advisoriesResultsCount.textContent = `Showing ${filteredAdvisories.length} of ${allAdvisories.length} advisories`;
    renderAdvisoryCards();
  }

  function getSeverity(adv) {
    if (adv.database_specific?.severity) return adv.database_specific.severity.toUpperCase();
    if (adv.affected?.[0]?.database_specific?.severity) return adv.affected[0].database_specific.severity.toUpperCase();
    return "UNKNOWN";
  }

  function getPackages(adv) {
    if (!adv.affected) return [];
    return adv.affected.map((a) => a.package?.name).filter(Boolean);
  }

  function getEcosystems(adv) {
    if (!adv.affected) return [];
    return adv.affected.map((a) => a.package?.ecosystem).filter(Boolean);
  }

  function renderAdvisoryCards() {
    if (filteredAdvisories.length === 0) {
      el.advisoriesContainer.innerHTML = `<div class="empty-state">No advisories match the current criteria.</div>`;
      return;
    }

    const toRender = filteredAdvisories.slice(0, 100);
    el.advisoriesContainer.innerHTML = toRender.map((adv) => {
      const sev = getSeverity(adv);
      const sevClass = `risk-${sev.toLowerCase()}`;
      const pkgs = getPackages(adv);

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
      card.addEventListener("click", () => openAdvisoryModal(card.dataset.id));
    });
  }

  function openAdvisoryModal(id) {
    const adv = allAdvisories.find((a) => a.id === id);
    if (!adv) return;
    el.modalId.textContent = adv.id;
    const sev = getSeverity(adv);
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

  // Initialize
  init();
})();
