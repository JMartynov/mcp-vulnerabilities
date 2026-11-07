import re

with open("src/mcp_vulnerabilities/pipeline.py", "r") as f:
    content = f.read()

sig_find = """        offline_fallback_fixtures: str | Path | None = None,
        reset_checkpoints: bool = False,
    ) -> PipelineResult:"""
sig_repl = """        offline_fallback_fixtures: str | Path | None = None,
        reset_checkpoints: bool = False,
        include_pruning: bool = False,
    ) -> PipelineResult:"""
content = content.replace(sig_find, sig_repl)

prune_logic_find = """        # 0. Pre-load historical advisories"""
prune_logic_repl = """        if include_pruning:
            from mcp_vulnerabilities.discovery.github_curated import GitHubCuratedDiscoveryProvider
            
            candidate_repos = []
            if self.servers_catalog_file.exists():
                try:
                    import json
                    cat_data = json.loads(self.servers_catalog_file.read_text(encoding="utf-8"))
                    for s in cat_data.get("servers", {}).values():
                        eco = s.get("ecosystem", "")
                        name = s.get("name", "")
                        repo = s.get("repository", "")
                        if eco and name and repo and eco.lower() == "github":
                            candidate_repos.append((eco, name, repo))
                except Exception as cat_e:
                    logger.debug("Catalog file parse error during pruning check: %s", cat_e)
            
            for eco, name, repo in candidate_repos:
                try:
                    is_dead = GitHubCuratedDiscoveryProvider.is_repository_archived_or_pruned(repo)
                    if is_dead:
                        logger.info("Pruning dead repository: %s", repo)
                        self.catalog_state.record_deprecation(eco, name, "deleted_404")
                except Exception as e:
                    logger.debug("Error checking repository status for %s: %s", repo, e)
            self.catalog_state.save()

        # 0. Pre-load historical advisories"""
content = content.replace(prune_logic_find, prune_logic_repl)

with open("src/mcp_vulnerabilities/pipeline.py", "w") as f:
    f.write(content)
