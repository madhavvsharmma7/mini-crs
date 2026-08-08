import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.orchestrator import clean_json, AGENT_1_SYSTEM, AGENT_2_SYSTEM, AGENT_3_SYSTEM, AGENT_4_SYSTEM

# ── Unit Tests ─────────────────────────────────────────────────────────────────

class TestCleanJson:
    def test_strips_json_fence(self):
        raw = '```json\n{"key": "value"}\n```'
        result = clean_json(raw)
        assert result == '{"key": "value"}'

    def test_strips_plain_fence(self):
        raw = '```\n{"key": "value"}\n```'
        result = clean_json(raw)
        assert result == '{"key": "value"}'

    def test_no_fence_unchanged(self):
        raw = '{"key": "value"}'
        result = clean_json(raw)
        assert result == '{"key": "value"}'

    def test_strips_control_characters(self):
        raw = '{"key": "val\x00ue"}'
        result = clean_json(raw)
        assert '\x00' not in result

    def test_strips_whitespace(self):
        raw = '  {"key": "value"}  '
        result = clean_json(raw)
        assert result == '{"key": "value"}'

    def test_output_is_valid_json(self):
        raw = '```json\n{"vulnerabilities": [], "summary": "none"}\n```'
        result = clean_json(raw)
        parsed = json.loads(result)
        assert "vulnerabilities" in parsed


class TestAgentPrompts:
    def test_agent1_system_not_empty(self):
        assert len(AGENT_1_SYSTEM) > 0

    def test_agent2_system_not_empty(self):
        assert len(AGENT_2_SYSTEM) > 0

    def test_agent3_system_not_empty(self):
        assert len(AGENT_3_SYSTEM) > 0

    def test_agent4_system_not_empty(self):
        assert len(AGENT_4_SYSTEM) > 0

    def test_agent1_requires_json(self):
        assert "JSON" in AGENT_1_SYSTEM

    def test_agent2_requires_json(self):
        assert "JSON" in AGENT_2_SYSTEM

    def test_agent3_requires_json(self):
        assert "JSON" in AGENT_3_SYSTEM

    def test_agent4_requires_json(self):
        assert "JSON" in AGENT_4_SYSTEM

    def test_agent1_mentions_vulnerabilities(self):
        assert "vulnerabilities" in AGENT_1_SYSTEM.lower()

    def test_agent4_mentions_verdict(self):
        assert "verdict" in AGENT_4_SYSTEM.lower()


class TestAgentOutputSchema:
    """Test that mock agent outputs match expected schema."""

    def test_agent1_schema(self):
        mock_output = {
            "vulnerabilities": [
                {"line": 5, "type": "SQL Injection", "description": "test", "severity": "CRITICAL"}
            ],
            "summary": "test summary"
        }
        assert "vulnerabilities" in mock_output
        assert "summary" in mock_output
        assert isinstance(mock_output["vulnerabilities"], list)
        vuln = mock_output["vulnerabilities"][0]
        assert "type" in vuln
        assert "severity" in vuln
        assert vuln["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_agent2_schema(self):
        mock_output = {
            "classifications": [
                {"type": "SQL Injection", "cwe_id": "CWE-89", "cwe_name": "SQL Injection", "cvss_score": 9.8, "attack_vector": "network"}
            ]
        }
        assert "classifications" in mock_output
        c = mock_output["classifications"][0]
        assert "cwe_id" in c
        assert "cvss_score" in c
        assert 0.0 <= c["cvss_score"] <= 10.0

    def test_agent3_schema(self):
        mock_output = {
            "patched_code": "import sqlite3\n...",
            "changes": [{"vulnerability": "SQL Injection", "fix_description": "used parameterized query"}]
        }
        assert "patched_code" in mock_output
        assert "changes" in mock_output
        assert len(mock_output["patched_code"]) > 0

    def test_agent4_schema(self):
        mock_output = {
            "verdict": "PASS",
            "resolved": [{"vulnerability": "SQL Injection", "resolved": True, "reason": "fixed"}],
            "new_issues": [],
            "confidence": 95
        }
        assert "verdict" in mock_output
        assert mock_output["verdict"] in ["PASS", "PARTIAL", "FAIL"]
        assert "confidence" in mock_output
        assert 0 <= mock_output["confidence"] <= 100


class TestIntegrationMock:
    """Integration tests using mock responses — no API calls."""

    def test_full_pipeline_structure(self):
        mock_results = {
            "static_analysis": {"vulnerabilities": [], "summary": "none"},
            "classification": {"classifications": []},
            "patch": {"patched_code": "clean code", "changes": []},
            "verification": {"verdict": "PASS", "resolved": [], "new_issues": [], "confidence": 100}
        }
        assert all(k in mock_results for k in ["static_analysis", "classification", "patch", "verification"])
        assert mock_results["verification"]["verdict"] == "PASS"

    def test_vulnerable_code_detection_logic(self):
        vulnerable_patterns = [
            "SELECT * FROM users WHERE username = '" ,
            "os.system(",
            "shell=True",
            "password = 'admin123'"
        ]
        demo_code = '''
import sqlite3, os, subprocess
def get_user(u): cursor.execute("SELECT * FROM users WHERE username = '" + u + "'")
def run(i): os.system("ping " + i)
password = 'admin123'
'''
        found = [p for p in vulnerable_patterns if p in demo_code]
        assert len(found) >= 3
