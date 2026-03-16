# 🔒 GHA Vulnerability Scanner

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

**Detect expression injection, GITHUB_ENV injection, and AI prompt injection vulnerabilities in GitHub Actions workflows.**

By [Sergio Cabrera](https://www.linkedin.com/in/sergio-cabrera-878766239/)

---

## ⚡ Install

```bash
pip install --force-reinstall git+https://github.com/nekros1xx/ghascan.git
```

That's it. Now set your token and scan:

```bash
export GITHUB_TOKEN="ghp_your_token_here"
ghascan --query 1
```

> Multiple tokens for faster scanning: `export GITHUB_TOKEN="token1,token2,token3"`

---

## 🎯 What It Detects

| Category | Examples | Severity |
|----------|---------|----------|
| **Expression injection** | `${{ github.event.issue.title }}` in `run:` blocks | CRITICAL/HIGH |
| **GITHUB_ENV injection** | Attacker input written to `$GITHUB_ENV` | MEDIUM/HIGH |
| **Indirect injection** | Tainted step outputs used in `run:` blocks | MEDIUM |
| **AI prompt injection** | Attacker input → AI action → output in `run:` block | AI_INJECTION |
| **Unpinned actions** | Third-party actions referenced by tag instead of SHA | Info |

### False Positive Elimination

7+ elimination rules minimize noise: commented code, disabled jobs/steps, trigger unreachability, safe contexts (`env:`, `with:`), exact-match gates, boolean expressions, quoted heredocs, per-job secrets scoping.

---

## 📖 Usage

### Query-based scan

```bash
ghascan --query 6                    # Issue body in run blocks
ghascan --all --min-stars 1000       # All 43 patterns, big repos only
ghascan --custom '"my_pattern" path:.github/workflows'
```

### Organization scan

```bash
ghascan --org Microsoft --min-stars 100
ghascan --org google --org-max-repos 200 --html report.html
```

### Offline analysis

```bash
ghascan --offline scan_data.json -v --verdict CRITICAL HIGH
```

### Output formats

```bash
ghascan --query 1 -o results.json    # JSON
ghascan --query 1 --html report.html # Interactive HTML
ghascan --query 1 --pdf report.pdf # PDF
```

Markdown is always generated alongside JSON automatically.

### Useful flags

```bash
--verdict CRITICAL HIGH   # Filter by severity
--min-stars 500           # Skip small repos
--limit 20                # Cap candidates (testing)
--clone                   # Git clone for deeper analysis
-v                        # Verbose output
```

---

## 🔍 43 Query Patterns

<details>
<summary>Click to expand</summary>

| # | Pattern | Target |
|---|---------|--------|
| 1-3 | PR title/body/head_ref in `run:` | `pull_request_target` |
| 4 | Comment body in `run:` | `issue_comment` |
| 5-6 | Issue title/body in `run:` | `issues` |
| 7-8 | Discussion title/body in `run:` | `discussion` |
| 9-10 | Review body/comment in `run:` | `pull_request_review` |
| 11-16 | `toJSON()` on parent objects | Various |
| 17-22 | `contains()`/`startsWith()` wrapping | Various |
| 23-24 | `format()` with attacker input | Various |
| 25-29 | Less common fields (labels, repo desc) | Various |
| 30 | `toJSON(steps)` in `run:` | Various |
| 31-35 | `github-script` + attacker input | Various |
| 36-38 | `GITHUB_ENV` injection | Various |
| 39-41 | Indirect injection via step outputs | Various |
| 42-43 | `workflow_dispatch` inputs | `workflow_dispatch` |

</details>

---

## 🏗️ Severity Levels

| Level | Meaning |
|-------|---------|
| **CRITICAL** | Full control + open trigger + custom secrets + no auth |
| **HIGH** | Full control + open trigger + GITHUB_TOKEN only |
| **MEDIUM** | Auth check present, restricted trigger, or dispatch-only |
| **LOW** | Limited control (head_ref), internal triggers, or read-only perms |
| **AI_INJECTION** | AI action output (tainted) used in executable context |
| **FALSE_POSITIVE** | All expressions eliminated by analysis rules |

---

## 🛡️ Responsible Disclosure

This tool is for **defensive security research**. If you find vulnerabilities, report them responsibly via the repo's Security tab. Do not exploit them.

---

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Sergio Cabrera** — [LinkedIn](https://www.linkedin.com/in/sergio-cabrera-878766239/) · [GitHub](https://github.com/sergio-cabrera)
