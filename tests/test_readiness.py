import pytest

from mcp_vulnerabilities.analyzers import ReadinessLinter, ReadinessReport


def test_rule_mcp_r001_missing_vague_description():
    linter = ReadinessLinter()
    # Missing description
    tool_bad = {"name": "query_db", "inputSchema": {}}
    issues = linter.lint_tool(tool_bad)
    assert any(i.rule_id == "MCP-R001" and i.severity == "CRITICAL" for i in issues)

    # Short/vague description (< 12 chars)
    tool_short = {"name": "query_db", "description": "run sql", "inputSchema": {}}
    issues = linter.lint_tool(tool_short)
    assert any(i.rule_id == "MCP-R001" and i.severity == "CRITICAL" for i in issues)

    # Valid description
    tool_good = {
        "name": "query_db",
        "description": "Executes parameterized SQL queries against the analytical database.",
        "inputSchema": {},
    }
    issues = linter.lint_tool(tool_good)
    assert not any(i.rule_id == "MCP-R001" for i in issues)


def test_rule_mcp_r002_untyped_parameters():
    linter = ReadinessLinter()
    tool = {
        "name": "search_items",
        "description": "Searches for catalog items with given criteria.",
        "inputSchema": {
            "type": "object",
            "required": ["query"],
            "properties": {
                "query": {"description": "Search query text"},  # missing type
                "filter": {"type": "any", "description": "Arbitrary filters"},  # type any
            },
        },
    }
    issues = linter.lint_tool(tool)
    untyped = [i for i in issues if i.rule_id == "MCP-R002"]
    assert len(untyped) == 2
    assert all(i.severity == "CRITICAL" for i in untyped)


def test_rule_mcp_r003_missing_required_array():
    linter = ReadinessLinter()
    tool = {
        "name": "fetch_record",
        "description": "Fetches a customer record by its identifier.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {"type": "string", "description": "Record ID"}
            },
            # Missing "required" array
        },
    }
    issues = linter.lint_tool(tool)
    assert any(i.rule_id == "MCP-R003" and i.severity == "CRITICAL" for i in issues)


def test_rule_mcp_r004_parameter_description_absence():
    linter = ReadinessLinter()
    tool = {
        "name": "fetch_record",
        "description": "Fetches a customer record by its identifier.",
        "inputSchema": {
            "type": "object",
            "required": ["id"],
            "properties": {
                "id": {"type": "string"}  # missing description for required param
            },
        },
    }
    issues = linter.lint_tool(tool)
    assert any(i.rule_id == "MCP-R004" and i.severity == "WARNING" for i in issues)


def test_rule_mcp_r005_unbounded_collections():
    linter = ReadinessLinter()
    tool = {
        "name": "batch_process",
        "description": "Processes batch records with optional concurrency limit.",
        "inputSchema": {
            "type": "object",
            "required": ["items"],
            "properties": {
                "items": {"type": "array", "description": "Array of item identifiers"},  # missing items schema
                "limit": {"type": "integer", "description": "Concurrency limit"},  # missing min/max
            },
        },
    }
    issues = linter.lint_tool(tool)
    assert any(i.rule_id == "MCP-R005" and i.severity == "WARNING" for i in issues)
    assert any(i.rule_id == "MCP-R005" and i.severity == "INFO" for i in issues)


def test_rule_mcp_r006_naming_conventions():
    linter = ReadinessLinter()
    # Bad characters / spaces
    tool_bad_name = {
        "name": "Fetch Records!",
        "description": "Fetches customer records from database.",
        "inputSchema": {},
    }
    issues = linter.lint_tool(tool_bad_name)
    assert any(i.rule_id == "MCP-R006" for i in issues)

    # Standard command collision
    tool_collision = {
        "name": "curl",
        "description": "Makes an HTTP request to remote server.",
        "inputSchema": {},
    }
    issues = linter.lint_tool(tool_collision)
    assert any(i.rule_id == "MCP-R006" for i in issues)


def test_rule_mcp_r007_mutating_error_contract():
    linter = ReadinessLinter()
    tool = {
        "name": "delete_customer",
        "description": "Deletes customer record from database.",
        "inputSchema": {},
    }
    issues = linter.lint_tool(tool)
    assert any(i.rule_id == "MCP-R007" and i.severity == "WARNING" for i in issues)


def test_scoring_and_grade_boundaries():
    linter = ReadinessLinter()
    # Perfect tool -> Score 100, Grade A
    perfect = {
        "name": "get_customer",
        "description": "Retrieves customer information by unique identifier.",
        "inputSchema": {
            "type": "object",
            "required": ["customer_id"],
            "properties": {
                "customer_id": {"type": "string", "description": "Unique customer ID"},
            },
        },
    }
    report = linter.lint_schema([perfect], "perfect_server")
    assert report.score == 100
    assert report.grade == "A"
    assert len(report.issues) == 0

    # 1 WARNING (-5) -> Score 95, Grade A
    # 2 WARNINGs (-10) -> Score 90, Grade A
    # 1 CRITICAL (-20) -> Score 80, Grade B
    # 1 CRITICAL + 1 WARNING (-25) -> Score 75, Grade C
    # 2 CRITICAL (-40) -> Score 60, Grade D
    # 3 CRITICAL (-60) -> Score 40, Grade F
