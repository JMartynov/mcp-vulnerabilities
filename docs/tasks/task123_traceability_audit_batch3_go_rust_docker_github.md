# Task 123: Track A — Batch 3 Traceability Audit: Go, Rust, Docker & GitHub Raw Servers (75 Items) (P0)

**Subsystem:** Polyglot Discovery & Ingestion (`docs/data/mcp_catalog_index.json`, `src/mcp_vulnerabilities/discovery/registries.py`, `src/mcp_vulnerabilities/discovery/github_curated.py`, `docs/reports/audit_batch3_polyglot.md`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave23_deep_empirical_audit_and_verification.md](master_plan_wave23_deep_empirical_audit_and_verification.md)

---

## 1. Objective & Problem Statement

Beyond the dominant JavaScript and Python ecosystems, the Model Context Protocol ecosystem contains high-performance native implementations and containerized distribution formats:
- **Go Ecosystem (120+ servers)**: High-concurrency stdio/SSE servers using Go (`github.com/modelcontextprotocol/go-sdk`, `mark3labs/mcp-go`).
- **Rust Ecosystem (29+ crates)**: Memory-safe CLI tools and embedded daemons distributed via `crates.io` (`rmcp`, `mcp-core`).
- **Docker Hub Containers (26+ images)**: Sandboxed MCP microservices packaged for turnkey execution via `docker run -i --rm`.
- **GitHub Raw Repositories (517+ servers)**: Direct GitHub repositories discovered via curated Awesome-lists (`punkpeye/awesome-mcp-servers`) that are not packaged in any centralized package registry.

These polyglot sources present distinct ingestion hazards:
1. **Go Module Path Disambiguation**: Go modules often reside in nested repository subdirectories (e.g. `github.com/siyuan-note/siyuan/kernel`), complicating repository clone and tag resolution.
2. **Crates.io Rate Limits & Crate Metadata**: The `crates.io` API requires strict User-Agent attribution and enforces rate limits. Some crates lack explicit repository links.
3. **Docker Hub Tagging Fluidity**: Docker Hub images commonly tag only `latest`, obscuring underlying software versioning and preventing SemVer vulnerability range checking.
4. **GitHub Unpackaged Staleness**: Direct GitHub repositories frequently change branch defaults (`master` vs `main`), archive repos, or abandon projects without formal release notices.

This task conducts an empirical upstream traceability audit across **75 real polyglot MCP servers** (25 Go, 20 Rust, 15 Docker, 15 GitHub Raw).

---

## 2. 7-Point Upstream Verification Protocol

Each package in Batch 3 is audited against the following 7 invariants:

1. **Upstream Canonical Endpoint Resolution**:
   - Go: Query `https://proxy.golang.org/<module>/@v/list` or GitHub repo API.
   - Rust: Query `https://crates.io/api/v1/crates/<crate_id>`.
   - Docker Hub: Query `https://hub.docker.com/v2/repositories/<repo>/tags`.
   - GitHub Raw: Query GitHub API `https://api.github.com/repos/<owner>/<repo>`.
2. **Version & Tag Alignment**:
   - Verify catalog `latest_version` against upstream git release tags or registry versions. Evaluate SemVer prefix handling (`v1.2.0` vs `1.2.0`).
3. **Repository URL & Branch Reachability**:
   - Verify that repository URLs point to active, non-archived git remotes returning HTTP 200.
4. **License & Author Attribution**:
   - Inspect upstream LICENSE files and package metadata to ensure correct attribution in catalog records.
5. **Transport Protocol Extraction**:
   - Confirm transport metadata: stdio command binary, Docker execution flags, or HTTP/SSE port configuration.
6. **Tool Capability Extraction**:
   - Determine how tool schemas are extracted (e.g. AST parsing of Go structs, Rust macros, or runtime probing).
7. **Security Posture & Vulnerability Correlation**:
   - Check cross-references in `docs/data/vulnerabilities.json` for Go/Rust ecosystem advisories.

---

## 3. Audited Item Registry: Batch 3 (75 Real Polyglot Packages)

| # | Package / Identifier | Ecosystem | Catalog Version | Upstream Repository / Homepage |
| :-: | :--- | :---: | :---: | :--- |
| 01 | `Blackman99/postsleuth` | `golang` | `v1.0.0` | [github.com/Blackman99/postsleuth](https://github.com/Blackman99/postsleuth) |
| 02 | `JoeGlenn1213/lgh` | `golang` | `v1.0.0` | [github.com/JoeGlenn1213/lgh](https://github.com/JoeGlenn1213/lgh) |
| 03 | `OrgMentem/zotio` | `golang` | `v1.0.0` | [github.com/OrgMentem/zotio](https://github.com/OrgMentem/zotio) |
| 04 | `Sudhan30/freshprobe` | `golang` | `v1.0.0` | [github.com/Sudhan30/freshprobe](https://github.com/Sudhan30/freshprobe) |
| 05 | `anwerj/youtube-uploader-mcp` | `golang` | `v1.0.0` | [github.com/anwerj/youtube-upload...](https://github.com/anwerj/youtube-uploader-mcp) |
| 06 | `blakerouse/ssh-mcp` | `golang` | `v1.0.0` | [github.com/blakerouse/ssh-mcp](https://github.com/blakerouse/ssh-mcp) |
| 07 | `chryaner/terrarium` | `golang` | `v1.0.0` | [github.com/chryaner/terrarium](https://github.com/chryaner/terrarium) |
| 08 | `corbym/backlog-mcp` | `golang` | `v1.0.0` | [github.com/corbym/backlog-mcp](https://github.com/corbym/backlog-mcp) |
| 09 | `desek/outlook-local-mcp` | `golang` | `v1.0.0` | [github.com/desek/outlook-local-mcp](https://github.com/desek/outlook-local-mcp) |
| 10 | `duaraghav8/MCPJungle` | `golang` | `v1.0.0` | [github.com/duaraghav8/MCPJungle](https://github.com/duaraghav8/MCPJungle) |
| 11 | `emicklei/melrose-mcp` | `golang` | `v1.0.0` | [github.com/emicklei/melrose-mcp](https://github.com/emicklei/melrose-mcp) |
| 12 | `gavelcode/gavel` | `golang` | `v1.0.0` | [github.com/gavelcode/gavel](https://github.com/gavelcode/gavel) |
| 13 | `github_0xJacky_nginx-ui` | `go` | `vlatest` | [github.com/0xJacky/nginx-ui](https://github.com/0xJacky/nginx-ui) |
| 14 | `github_geekjourneyx_md2wechat-skill` | `go` | `vlatest` | [github.com/geekjourneyx/md2wecha...](https://github.com/geekjourneyx/md2wechat-skill) |
| 15 | `github_txn2_kubefwd` | `go` | `vlatest` | [github.com/txn2/kubefwd](https://github.com/txn2/kubefwd) |
| 16 | `hloiseaufcms/mcp-gopls` | `golang` | `v1.0.0` | [github.com/hloiseaufcms/mcp-gopls](https://github.com/hloiseaufcms/mcp-gopls) |
| 17 | `isaacphi/mcp-language-server` | `golang` | `v1.0.0` | [github.com/isaacphi/mcp-language...](https://github.com/isaacphi/mcp-language-server) |
| 18 | `kambriso/fritzbox-mcp-server` | `golang` | `v1.0.0` | [github.com/kambriso/fritzbox-mcp...](https://github.com/kambriso/fritzbox-mcp-server) |
| 19 | `lightpanda-io/gomcp` | `golang` | `v1.0.0` | [github.com/lightpanda-io/gomcp](https://github.com/lightpanda-io/gomcp) |
| 20 | `metoro-io/metoro-mcp-server` | `golang` | `v1.0.0` | [github.com/metoro-io/metoro-mcp-...](https://github.com/metoro-io/metoro-mcp-server) |
| 21 | `mrjoshuak/godoc-mcp` | `golang` | `v1.0.0` | [github.com/mrjoshuak/godoc-mcp](https://github.com/mrjoshuak/godoc-mcp) |
| 22 | `nnemirovsky/iwdp-mcp` | `golang` | `v1.0.0` | [github.com/nnemirovsky/iwdp-mcp](https://github.com/nnemirovsky/iwdp-mcp) |
| 23 | `planetscale/cli` | `golang` | `v1.0.0` | [github.com/planetscale/cli](https://github.com/planetscale/cli) |
| 24 | `raohwork/forgejo-mcp` | `golang` | `v1.0.0` | [github.com/raohwork/forgejo-mcp](https://github.com/raohwork/forgejo-mcp) |
| 25 | `seekrays/mcp-monitor` | `golang` | `v1.0.0` | [github.com/seekrays/mcp-monitor](https://github.com/seekrays/mcp-monitor) |
| 26 | `abcop` | `cargo` | `v0.19.1` | [github.com/adrianov/abcop](https://github.com/adrianov/abcop) |
| 27 | `abnegate-agent` | `cargo` | `v0.1.4` | [github.com/abnegate/crates](https://github.com/abnegate/crates) |
| 28 | `abyo-hippo` | `cargo` | `v0.0.1` | [github.com/abyo-software/claude-...](https://github.com/abyo-software/claude-hippo) |
| 29 | `adbridge` | `cargo` | `v0.1.1` | [github.com/Slush97/adbridge](https://github.com/Slush97/adbridge) |
| 30 | `adk-mcp-github` | `cargo` | `v1.4.0` | [github.com/zavora-ai/adk-mcp-github](https://github.com/zavora-ai/adk-mcp-github) |
| 31 | `aerosync` | `cargo` | `v0.1.0` | [github.com/TechVerseOdyssey/Aero...](https://github.com/TechVerseOdyssey/AeroSync) |
| 32 | `aerosync-mcp` | `cargo` | `v0.1.0` | [github.com/TechVerseOdyssey/Aero...](https://github.com/TechVerseOdyssey/AeroSync) |
| 33 | `afd` | `cargo` | `v0.1.0` | [github.com/lushly-dev/afd](https://github.com/lushly-dev/afd) |
| 34 | `arete-mcp` | `cargo` | `v0.42.0` | [github.com/AreteA4/arete.git](https://github.com/AreteA4/arete.git) |
| 35 | `computer-use-linux` | `cargo` | `v0.7.20` | [github.com/agent-sh/computer-use...](https://github.com/agent-sh/computer-use-linux) |
| 36 | `embacle` | `cargo` | `v0.38.0` | [github.com/dravr-ai/dravr-embacle](https://github.com/dravr-ai/dravr-embacle) |
| 37 | `fastmcp-server` | `cargo` | `v0.13.0` | [github.com/Dicklesworthstone/fas...](https://github.com/Dicklesworthstone/fastmcp_rust) |
| 38 | `github_0xMassi_webclaw` | `cargo` | `vlatest` | [github.com/0xMassi/webclaw](https://github.com/0xMassi/webclaw) |
| 39 | `github_blacktop_ida-mcp-rs` | `cargo` | `vlatest` | [github.com/blacktop/ida-mcp-rs](https://github.com/blacktop/ida-mcp-rs) |
| 40 | `github_fabio-rovai_open-ontologies` | `cargo` | `vlatest` | [github.com/fabio-rovai/open-onto...](https://github.com/fabio-rovai/open-ontologies) |
| 41 | `github_fastcrw_crw` | `cargo` | `vlatest` | [github.com/fastcrw/crw](https://github.com/fastcrw/crw) |
| 42 | `github_hyper-mcp-rs_hyper-mcp` | `cargo` | `vlatest` | [github.com/hyper-mcp-rs/hyper-mcp](https://github.com/hyper-mcp-rs/hyper-mcp) |
| 43 | `github_microsoft_wassette` | `cargo` | `vlatest` | [github.com/microsoft/wassette](https://github.com/microsoft/wassette) |
| 44 | `github_mixelpixx_Konnect` | `cargo` | `vlatest` | [github.com/mixelpixx/Konnect](https://github.com/mixelpixx/Konnect) |
| 45 | `github_modelcontextprotocol_rust-sdk` | `cargo` | `vlatest` | [github.com/modelcontextprotocol/...](https://github.com/modelcontextprotocol/rust-sdk) |
| 46 | `docker_mcp_api-gateway` | `docker` | `vlatest` | [hub.docker.com/r/mcp/api-gateway](https://hub.docker.com/r/mcp/api-gateway) |
| 47 | `docker_mcp_arxiv-mcp-server` | `docker` | `vlatest` | [hub.docker.com/r/mcp/arxiv-mcp-s...](https://hub.docker.com/r/mcp/arxiv-mcp-server) |
| 48 | `docker_mcp_aws-core-mcp-server` | `docker` | `vlatest` | [hub.docker.com/r/mcp/aws-core-mc...](https://hub.docker.com/r/mcp/aws-core-mcp-server) |
| 49 | `docker_mcp_clickhouse` | `docker` | `vlatest` | [hub.docker.com/r/mcp/clickhouse](https://hub.docker.com/r/mcp/clickhouse) |
| 50 | `docker_mcp_context7` | `docker` | `vlatest` | [hub.docker.com/r/mcp/context7](https://hub.docker.com/r/mcp/context7) |
| 51 | `docker_mcp_dockerhub` | `docker` | `vlatest` | [hub.docker.com/r/mcp/dockerhub](https://hub.docker.com/r/mcp/dockerhub) |
| 52 | `docker_mcp_duckduckgo` | `docker` | `vlatest` | [hub.docker.com/r/mcp/duckduckgo](https://hub.docker.com/r/mcp/duckduckgo) |
| 53 | `docker_mcp_dynatrace-mcp-server` | `docker` | `vlatest` | [hub.docker.com/r/mcp/dynatrace-m...](https://hub.docker.com/r/mcp/dynatrace-mcp-server) |
| 54 | `docker_mcp_fetch` | `docker` | `vlatest` | [hub.docker.com/r/mcp/fetch](https://hub.docker.com/r/mcp/fetch) |
| 55 | `docker_mcp_firecrawl` | `docker` | `vlatest` | [hub.docker.com/r/mcp/firecrawl](https://hub.docker.com/r/mcp/firecrawl) |
| 56 | `docker_mcp_grafana` | `docker` | `vlatest` | [hub.docker.com/r/mcp/grafana](https://hub.docker.com/r/mcp/grafana) |
| 57 | `docker_mcp_hackernews-mcp` | `docker` | `vlatest` | [hub.docker.com/r/mcp/hackernews-mcp](https://hub.docker.com/r/mcp/hackernews-mcp) |
| 58 | `docker_mcp_markitdown` | `docker` | `vlatest` | [hub.docker.com/r/mcp/markitdown](https://hub.docker.com/r/mcp/markitdown) |
| 59 | `docker_mcp_mcp-code-interpreter` | `docker` | `vlatest` | [hub.docker.com/r/mcp/mcp-code-in...](https://hub.docker.com/r/mcp/mcp-code-interpreter) |
| 60 | `docker_mcp_mcp-discord` | `docker` | `vlatest` | [hub.docker.com/r/mcp/mcp-discord](https://hub.docker.com/r/mcp/mcp-discord) |
| 61 | `0xUXDesign/pharaoh-mcp` | `github` | `v1.0.0` | [github.com/0xUXDesign/pharaoh-mcp](https://github.com/0xUXDesign/pharaoh-mcp) |
| 62 | `Dipeshpal/capes` | `github` | `v1.0.0` | [github.com/Dipeshpal/capes](https://github.com/Dipeshpal/capes) |
| 63 | `KuvopLLC/better-bear` | `github` | `v1.0.0` | [smithery.ai/servers/KuvopLLC/bet...](https://smithery.ai/servers/KuvopLLC/better-bear) |
| 64 | `SaintDoresh/Crypto-Trader-MCP-ClaudeDesktop.git` | `github` | `v1.0.0` | [github.com/SaintDoresh/Crypto-Tr...](https://github.com/SaintDoresh/Crypto-Trader-MCP-ClaudeDesktop.git) |
| 65 | `alexcloudstar/makers.page-mcp` | `github` | `v1.0.0` | [github.com/alexcloudstar/makers....](https://github.com/alexcloudstar/makers.page-mcp) |
| 66 | `cmcgrabby-hue/syndicate-links` | `github` | `v1.0.0` | [github.com/cmcgrabby-hue/syndica...](https://github.com/cmcgrabby-hue/syndicate-links) |
| 67 | `evan-moon/firma` | `github` | `v1.0.0` | [github.com/evan-moon/firma](https://github.com/evan-moon/firma) |
| 68 | `github_NanGePlus_MCPTest` | `github` | `vlatest` | [github.com/NanGePlus/MCPTest](https://github.com/NanGePlus/MCPTest) |
| 69 | `github_qiye45_wechatDownload` | `github` | `vlatest` | [github.com/qiye45/wechatDownload](https://github.com/qiye45/wechatDownload) |
| 70 | `j3k0/speech.sh` | `github` | `v1.0.0` | [github.com/j3k0/speech.sh](https://github.com/j3k0/speech.sh) |
| 71 | `likidodefi/riskstate-mcp` | `github` | `v1.0.0` | [github.com/likidodefi/riskstate-mcp](https://github.com/likidodefi/riskstate-mcp) |
| 72 | `nipun-arora/wordpress-mcp-agent-bridge` | `github` | `v1.0.0` | [github.com/nipun-arora/wordpress...](https://github.com/nipun-arora/wordpress-mcp-agent-bridge) |
| 73 | `rhein1/agoragentic-integrations` | `github` | `v1.0.0` | [github.com/rhein1/agoragentic-in...](https://github.com/rhein1/agoragentic-integrations) |
| 74 | `softvoyagers/pagedrop-api` | `github` | `v1.0.0` | [github.com/softvoyagers/pagedrop...](https://github.com/softvoyagers/pagedrop-api) |
| 75 | `trayders/trayd-mcp` | `github` | `v1.0.0` | [github.com/trayders/trayd-mcp](https://github.com/trayders/trayd-mcp) |

---

## 4. Automated Verification & Acceptance Test Suite

An automated audit invariant test suite must be established in `tests/audit/test_traceability_batch3_polyglot.py`:

```python
"""Empirical Traceability Test Suite for Batch 3 (Go, Rust, Docker & GitHub Raw MCP Servers)."""

import json
from pathlib import Path
import pytest

CATALOG_PATH = Path("docs/data/mcp_catalog_index.json")

@pytest.fixture(scope="module")
def catalog_index():
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch3_polyglot_ecosystems_represented(catalog_index):
    # Verify Go, Rust, Docker, and GitHub ecosystems exist with valid metadata
    ecos = {s.get("ecosystem") for s in catalog_index}
    assert "golang" in ecos or "go" in ecos or "Go" in ecos
    assert "cargo" in ecos
    assert "docker" in ecos
    assert "github" in ecos
```

---

## 5. Deliverables & Integration Checklist

- [ ] Execute upstream verification across all 75 polyglot endpoints.
- [ ] Record findings in `docs/reports/audit_batch3_polyglot.md` detailing:
  - Upstream reachability matrix for Go, Rust, Docker, and GitHub repositories.
  - Identification of archived or deleted GitHub repositories.
  - Docker Hub tag versioning strategy and recommendation for digest pinning.
  - SemVer normalization across Go (`v`-prefixed) and Cargo crates.
- [ ] Implement automated regression test `tests/audit/test_traceability_batch3_polyglot.py`.
- [ ] Recommend enhancements to `src/mcp_vulnerabilities/discovery/registries.py` and `github_curated.py`.
