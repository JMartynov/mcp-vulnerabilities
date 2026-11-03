from mcp_vulnerabilities.discovery.gitlab import GitLabAdvisorySync

sync = GitLabAdvisorySync("tests/fixtures/osv")
# just testing the setup
print(sync.target_ecosystems)
