import pytest
from mcp_vulnerabilities.analyzers.typosquat import TyposquatDetector, RiskTier, get_default_corpus

@pytest.fixture
def detector():
    corpus = get_default_corpus()
    return TyposquatDetector(corpus)

def test_invariant_97_1c_authentic(detector):
    res = detector.analyze("@modelcontextprotocol/server-filesystem")
    assert res.risk_tier == RiskTier.AUTHENTIC
    assert res.reason == "Exact match"

def test_invariant_97_1a_distance_1(detector):
    res = detector.analyze("@modelcontextprotocol/server-filesytem")
    assert res.risk_tier == RiskTier.HIGH
    assert res.reason == "HIGH_RISK_TYPOSQUAT"
    assert res.canonical_name == "@modelcontextprotocol/server-filesystem"
    assert res.distance == 1

    res2 = detector.analyze("mcp-server-sqlte")
    assert res2.risk_tier == RiskTier.HIGH
    assert res2.reason == "HIGH_RISK_TYPOSQUAT"
    assert res2.canonical_name == "mcp-server-sqlite"
    assert res2.distance == 1

def test_invariant_97_1b_permutation(detector):
    # corpus has "mcp-server-filesystem" - wait, let's add it to corpus first
    detector.corpus.add("mcp-server-filesystem")
    res = detector.analyze("filesystem-mcp-server")
    assert res.risk_tier == RiskTier.SUSPICIOUS
    assert res.reason == "SUSPICIOUS_NAMING_PERMUTATION"
    assert res.canonical_name == "mcp-server-filesystem"

def test_invariant_97_2a_homoglyph(detector):
    # Cyrillic 'с' (U+0441)
    malicious = "mсp-server-sqlite" 
    res = detector.analyze(malicious)
    assert res.risk_tier == RiskTier.CRITICAL
    assert res.reason == "CRITICAL_HOMOGLYPH_ATTACK"
    assert res.canonical_name == "mcp-server-sqlite"

import json
import subprocess
import os

def test_invariant_97_3a_cli_exit_codes(tmp_path):
    config = {
      "mcpServers": {
        "sqlite": {
          "command": "npx",
          "args": ["-y", "mcp-server-sqlte"]
        }
      }
    }
    config_path = tmp_path / "config.json"
    with open(config_path, "w") as f:
        json.dump(config, f)
        
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    res = subprocess.run(["python3", "src/mcp_vulnerabilities/cli.py", "audit-typosquat", "--config", str(config_path)], env=env, capture_output=True)
    assert res.returncode == 1

def test_invariant_97_3b_cli_fix(tmp_path):
    config = {
      "mcpServers": {
        "sqlite": {
          "command": "npx",
          "args": ["-y", "mcp-server-sqlte"]
        }
      }
    }
    config_path = tmp_path / "config.json"
    with open(config_path, "w") as f:
        json.dump(config, f)
        
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    res = subprocess.run(["python3", "src/mcp_vulnerabilities/cli.py", "audit-typosquat", "--config", str(config_path), "--fix"], env=env, capture_output=True)
    assert res.returncode == 1
    
    with open(config_path, "r") as f:
        fixed = json.load(f)
    assert fixed["mcpServers"]["sqlite"]["args"][1] == "mcp-server-sqlite"

def test_invariant_97_3c_cli_json(tmp_path):
    config = {
      "mcpServers": {
        "sqlite": {
          "command": "npx",
          "args": ["-y", "mcp-server-sqlte"]
        }
      }
    }
    config_path = tmp_path / "config.json"
    with open(config_path, "w") as f:
        json.dump(config, f)
        
    env = os.environ.copy()
    env["PYTHONPATH"] = "src"
    res = subprocess.run(["python3", "src/mcp_vulnerabilities/cli.py", "audit-typosquat", "--config", str(config_path), "--json"], env=env, capture_output=True, text=True)
    
    data = json.loads(res.stdout)
    assert "analyzed_packages" in data
    assert "typosquats_detected" in data
    assert "risk_summary" in data

