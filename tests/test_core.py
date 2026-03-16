"""Tests for gha-vuln-scanner core analysis."""
import pytest


def test_version():
    from gha_vuln_scanner import __version__, __author__
    assert __version__ == "3.5.0"
    assert __author__ == "Sergio Cabrera"


def test_classify_expression_full_control():
    from gha_vuln_scanner.scanner import classify_expression
    assert classify_expression("${{ github.event.issue.title }}") == "FULL_CONTROL"
    assert classify_expression("${{ github.event.comment.body }}") == "FULL_CONTROL"
    assert classify_expression("${{ github.event.pull_request.body }}") == "FULL_CONTROL"


def test_classify_expression_no_control():
    from gha_vuln_scanner.scanner import classify_expression
    assert classify_expression("${{ github.event.issue.number }}") == "NO_CONTROL"
    assert classify_expression("${{ github.actor }}") == "NO_CONTROL"
    assert classify_expression("${{ github.sha }}") == "NO_CONTROL"


def test_classify_expression_limited():
    from gha_vuln_scanner.scanner import classify_expression
    assert classify_expression("${{ github.head_ref }}") == "LIMITED_CONTROL"


def test_classify_expression_boolean():
    from gha_vuln_scanner.scanner import classify_expression
    assert classify_expression("${{ github.event.issue.title == 'test' }}") == "NO_CONTROL"
    assert classify_expression("${{ contains(github.event.comment.body, '/approve') }}") == "NO_CONTROL"


def test_classify_dispatch_input():
    from gha_vuln_scanner.scanner import classify_expression
    assert classify_expression("${{ github.event.inputs.my-input }}") == "DISPATCH_INPUT"
    assert classify_expression("${{ inputs.my-input }}") == "DISPATCH_INPUT"


def test_is_boolean_result():
    from gha_vuln_scanner.scanner import _is_boolean_result
    assert _is_boolean_result("${{ github.event.pull_request.merged == true }}") is True
    assert _is_boolean_result("${{ contains(github.event.comment.body, '/deploy') }}") is True
    assert _is_boolean_result("${{ !github.event.pull_request.draft }}") is True
    assert _is_boolean_result("${{ github.event.issue.title }}") is False


def test_scan_expressions_in_run():
    from gha_vuln_scanner.scanner import scan_expressions
    workflow = """name: test
on:
  issues:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "Title: ${{ github.event.issue.title }}"
"""
    results = scan_expressions(workflow)
    assert len(results) >= 1
    assert any("github.event.issue.title" in r["expression"] for r in results)


def test_scan_expressions_safe_env():
    from gha_vuln_scanner.scanner import scan_expressions
    workflow = """name: test
on:
  issues:
    types: [opened]
jobs:
  test:
    runs-on: ubuntu-latest
    env:
      TITLE: ${{ github.event.issue.title }}
    steps:
      - run: echo "safe"
"""
    results = scan_expressions(workflow)
    # Should NOT find expression in env: block
    assert len(results) == 0


def test_parse_triggers():
    from gha_vuln_scanner.scanner import parse_triggers
    content = """on:
  issues:
    types: [opened, edited]
  pull_request_target:
"""
    triggers = parse_triggers(content)
    assert "issues" in triggers
    assert "pull_request_target" in triggers


def test_token_module_no_hardcoded():
    """Verify no hardcoded tokens exist in the package."""
    import gha_vuln_scanner.tokens as tokens
    import inspect
    source = inspect.getsource(tokens)
    assert "ghp_" not in source
    assert "github_pat_" not in source


def test_constants_queries():
    from gha_vuln_scanner.constants import QUERIES
    assert len(QUERIES) == 43
    assert 1 in QUERIES
    assert 43 in QUERIES


def test_ctrl_label():
    from gha_vuln_scanner.constants import ctrl_label, ctrl_explain
    assert ctrl_label("FULL_CONTROL") == "attacker-controlled"
    assert "arbitrary" in ctrl_explain("FULL_CONTROL")
    assert ctrl_label("NO_CONTROL") == "not-controlled"
