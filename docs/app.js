// MCP Security Vulnerability Explorer Application

(function () {
  let allAdvisories = [];
  let filteredAdvisories = [];
  let activeSeverity = "ALL";
  let activeEcosystem = "ALL";
  let searchQuery = "";

  const elements = {
    total: document.getElementById("stat-total"),
    critical: document.getElementById("stat-critical"),
    high: document.getElementById("stat-high"),
    packages: document.getElementById("stat-packages"),
    searchInput: document.getElementById("search-input"),
    severityChips: document.getElementById("severity-chips"),
    ecosystemChips: document.getElementById("ecosystem-chips"),
    container: document.getElementById("advisories-container"),
    resultsCount: document.getElementById("results-count"),
    modal: document.getElementById("advisory-modal"),
    modalClose: document.getElementById("modal-close"),
    modalId: document.getElementById("modal-id"),
    modalSeverity: document.getElementById("modal-severity"),
    modalBody: document.getElementById("modal-body"),
    modalExternalLink: document.getElementById("modal-external-link"),
  };

  async function init() {
    setupEventListeners();
    await loadData();
  }

  async function loadData() {
    try {
      const response = await fetch("data/vulnerabilities.json");
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}`);
      }
      allAdvisories = await response.json();
      updateMetrics();
      applyFilters();
    } catch (err) {
      console.warn("Failed to load data/vulnerabilities.json directly, attempting fallback:", err);
      elements.container.innerHTML = `
        <div class="loading-state" style="color: #ef4444;">
          Unable to load static vulnerabilities dataset directly. Please ensure <code>python -m mcp_vulnerabilities.site_builder</code> has been run.
        </div>
      `;
    }
  }

  function getSeverity(adv) {
    if (adv.database_specific?.severity) {
      return adv.database_specific.severity.toUpperCase();
    }
    if (adv.affected?.[0]?.database_specific?.severity) {
      return adv.affected[0].database_specific.severity.toUpperCase();
    }
    const score = getCvssScore(adv);
    if (score !== null) {
      if (score >= 9.0) return "CRITICAL";
      if (score >= 7.0) return "HIGH";
      if (score >= 4.0) return "MEDIUM";
      return "LOW";
    }
    return "UNKNOWN";
  }

  function getCvssScore(adv) {
    const rawScore = adv.severity?.[0]?.score || adv.affected?.[0]?.database_specific?.cvss_score;
    const parsed = parseFloat(rawScore);
    return isNaN(parsed) ? null : parsed;
  }

  function getPackages(adv) {
    if (!adv.affected) return [];
    return adv.affected
      .map((aff) => aff.package?.name)
      .filter(Boolean);
  }

  function getEcosystems(adv) {
    if (!adv.affected) return [];
    return adv.affected
      .map((aff) => aff.package?.ecosystem)
      .filter(Boolean);
  }

  function updateMetrics() {
    let crit = 0;
    let high = 0;
    const pkgs = new Set();

    allAdvisories.forEach((adv) => {
      const sev = getSeverity(adv);
      if (sev === "CRITICAL") crit++;
      if (sev === "HIGH") high++;
      getPackages(adv).forEach((p) => pkgs.add(p.toLowerCase()));
    });

    elements.total.textContent = allAdvisories.length;
    elements.critical.textContent = crit;
    elements.high.textContent = high;
    elements.packages.textContent = pkgs.size;
  }

  function applyFilters() {
    filteredAdvisories = allAdvisories.filter((adv) => {
      // 1. Severity filter
      const sev = getSeverity(adv);
      if (activeSeverity !== "ALL" && sev !== activeSeverity) {
        return false;
      }

      // 2. Ecosystem filter
      if (activeEcosystem !== "ALL") {
        const ecos = getEcosystems(adv).map((e) => e.toLowerCase());
        if (!ecos.includes(activeEcosystem.toLowerCase())) {
          return false;
        }
      }

      // 3. Search query
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        const idMatch = adv.id?.toLowerCase().includes(q);
        const summaryMatch = (adv.summary || "").toLowerCase().includes(q);
        const detailsMatch = (adv.details || "").toLowerCase().includes(q);
        const pkgMatch = getPackages(adv).some((p) => p.toLowerCase().includes(q));
        if (!idMatch && !summaryMatch && !detailsMatch && !pkgMatch) {
          return false;
        }
      }

      return true;
    });

    renderAdvisories();
  }

  function renderAdvisories() {
    elements.resultsCount.textContent = `Showing ${filteredAdvisories.length} of ${allAdvisories.length} advisories`;

    if (filteredAdvisories.length === 0) {
      elements.container.innerHTML = `
        <div class="loading-state">
          No vulnerabilities match the selected filters or search query.
        </div>
      `;
      return;
    }

    elements.container.innerHTML = filteredAdvisories
      .map((adv) => {
        const sev = getSeverity(adv);
        const pkgs = getPackages(adv);
        const date = (adv.published || adv.modified || "").split("T")[0];
        const summary = adv.summary || (adv.details || "").slice(0, 140) + "...";
        const badgeClass = `badge-${sev.toLowerCase()}`;

        return `
          <div class="advisory-card" data-id="${adv.id}">
            <div class="card-top">
              <div class="card-ids">
                <span class="adv-id">${adv.id}</span>
                <span class="badge ${badgeClass}">${sev}</span>
              </div>
              <span class="card-date">${date}</span>
            </div>
            <div class="card-title">${escapeHtml(summary)}</div>
            <div class="card-meta">
              <span>Packages: ${pkgs.map((p) => `<span class="meta-pkg">${escapeHtml(p)}</span>`).join(" ")}</span>
            </div>
          </div>
        `;
      })
      .join("");

    // Attach card click handlers
    elements.container.querySelectorAll(".advisory-card").forEach((card) => {
      card.addEventListener("click", () => {
        const advId = card.getAttribute("data-id");
        const found = allAdvisories.find((a) => a.id === advId);
        if (found) openModal(found);
      });
    });
  }

  function openModal(adv) {
    const sev = getSeverity(adv);
    const score = getCvssScore(adv);
    const pkgs = getPackages(adv);
    const externalUrl = adv.references?.[0]?.url || `https://github.com/JMartynov/mcp-vulnerabilities/blob/main/data/vulnerabilities/${adv.id}.json`;

    elements.modalId.textContent = adv.id;
    elements.modalSeverity.textContent = sev + (score ? ` (CVSS ${score})` : "");
    elements.modalSeverity.className = `badge badge-${sev.toLowerCase()}`;
    elements.modalExternalLink.href = externalUrl;

    const sections = [];

    if (adv.summary) {
      sections.push(`
        <div class="modal-section">
          <h4>Summary</h4>
          <p>${escapeHtml(adv.summary)}</p>
        </div>
      `);
    }

    sections.push(`
      <div class="modal-section">
        <h4>Affected Packages & Versions</h4>
        ${(adv.affected || [])
          .map((aff) => {
            const pkgName = aff.package?.name || "Unknown";
            const eco = aff.package?.ecosystem || "Generic";
            const ranges = (aff.ranges || [])
              .map((r) => {
                const events = (r.events || []).map((e) => JSON.stringify(e)).join(", ");
                return `Type: ${r.type} (${events})`;
              })
              .join("<br>");
            return `<p><strong>${escapeHtml(pkgName)}</strong> (${eco})<br>${ranges || "All versions"}</p>`;
          })
          .join("")}
      </div>
    `);

    if (adv.details) {
      sections.push(`
        <div class="modal-section">
          <h4>Vulnerability Details</h4>
          <div class="code-box">${escapeHtml(adv.details)}</div>
        </div>
      `);
    }

    if (adv.references && adv.references.length > 0) {
      sections.push(`
        <div class="modal-section">
          <h4>References</h4>
          <ul>
            ${adv.references
              .map((r) => `<li><a href="${escapeHtml(r.url)}" target="_blank" rel="noopener">${escapeHtml(r.url)}</a></li>`)
              .join("")}
          </ul>
        </div>
      `);
    }

    elements.modalBody.innerHTML = sections.join("");
    elements.modal.showModal();
  }

  function setupEventListeners() {
    // Search input debounce
    let timeout;
    elements.searchInput.addEventListener("input", (e) => {
      clearTimeout(timeout);
      timeout = setTimeout(() => {
        searchQuery = e.target.value.trim();
        applyFilters();
      }, 150);
    });

    // Severity chips
    elements.severityChips.querySelectorAll(".chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        elements.severityChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        activeSeverity = chip.getAttribute("data-severity");
        applyFilters();
      });
    });

    // Ecosystem chips
    elements.ecosystemChips.querySelectorAll(".chip").forEach((chip) => {
      chip.addEventListener("click", () => {
        elements.ecosystemChips.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
        chip.classList.add("active");
        activeEcosystem = chip.getAttribute("data-ecosystem");
        applyFilters();
      });
    });

    // Modal close
    elements.modalClose.addEventListener("click", () => elements.modal.close());
    elements.modal.addEventListener("click", (e) => {
      if (e.target === elements.modal) elements.modal.close();
    });
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  document.addEventListener("DOMContentLoaded", init);
})();
