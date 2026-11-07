# Task 164: AST Call-Graph Reachability Tagging in Passport Builder

## Objective
Implement `src/mcp_vulnerabilities/passport/builder.py` (`PassportBuilder`) to integrate AST call-graph reachability analysis with MCP passport generation, distinguishing between reachable tool handlers and dormant transitive library dependencies.

## Background & Issues Identified
- The AST call-graph reachability analyzer exists in `src/mcp_vulnerabilities/analyzers/reachability/call_graph.py` and AST taint scanner in `ast_taint/`, but `src/mcp_vulnerabilities/passport/builder.py` was never created.
- Server passports generated for `data/passports.json.gz` lack fine-grained reachability flags (`reachable_via_tool: bool`), causing dormant transitive library vulnerabilities to be penalized as heavily as direct tool exploits.

## Scope of Changes
1. `src/mcp_vulnerabilities/passport/builder.py`:
   - Implement `PassportBuilder` with `build_from_source(repo_path: Path, package_name: str, ecosystem: str) -> ServerPackageSpec`.
   - Call `AstReachabilityAnalyzer.analyze_directory(repo_path)` and `McpSourceScanner(repo_path).scan()`.
   - Annotate findings and imported dependencies with `reachable_via_tool: bool` and reachable call paths.
2. `src/mcp_vulnerabilities/scoring.py`:
   - Update `calculate_trust_score` / `CompositeRiskScorer` to utilize `reachable_via_tool` annotations: discount or cap unreachable library vulnerabilities while maintaining full weight for reachable/direct vulnerabilities.
3. `tests/test_passport_builder_reachability.py`:
   - Unit tests with mock MCP source code asserting that tool-reachable symbols are marked `reachable_via_tool=True` while dormant helper dependencies are marked `reachable_via_tool=False`.

## Acceptance Criteria
- `PassportBuilder.build_from_source()` outputs valid `ServerPackageSpec` with reachability matrix.
- `calculate_trust_score()` properly applies reachability weighting.
- `pytest tests/test_passport_builder_reachability.py` passes 100%.
