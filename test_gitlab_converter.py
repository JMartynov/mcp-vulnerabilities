from mcp_vulnerabilities.converters.gitlab import GitLabAdvisoryConverter

def test_conversion():
    v = GitLabAdvisoryConverter.from_file("tests/fixtures/osv/gitlab/CVE-2024-54133.yml")
    print(v.id)
    print(v.aliases)
    print(v.affected[0].package.ecosystem)
    print(v.affected[0].package.purl)
    print(v.affected[0].ranges[0].events)
    print(v.severity[0].score)
    print(v.database_specific.get("remediation"))
    print(v.database_specific.get("gitlab_uuid"))
    
test_conversion()
