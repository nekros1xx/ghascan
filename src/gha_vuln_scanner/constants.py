"""
Constants: queries, patterns, expression classification sets, and configuration.
"""

import re

# ── Queries for GitHub Code Search API ──────────────────────────────
QUERIES = {
    1:  ("PR title in run (PRT)",
         '"pull_request_target" "${{ github.event.pull_request.title }}" "run:" path:.github/workflows'),
    2:  ("PR body in run (PRT)",
         '"pull_request_target" "${{ github.event.pull_request.body }}" "run:" path:.github/workflows'),
    3:  ("Head ref in run (PRT)",
         '"pull_request_target" "${{ github.head_ref }}" "run:" path:.github/workflows'),
    4:  ("Comment body in run (issue_comment)",
         '"issue_comment" "${{ github.event.comment.body }}" "run:" path:.github/workflows'),
    5:  ("Issue title in run",
         '"issues" "${{ github.event.issue.title }}" "run:" path:.github/workflows'),
    6:  ("Issue body in run",
         '"issues" "${{ github.event.issue.body }}" "run:" path:.github/workflows'),
    7:  ("Discussion title in run",
         '"discussion" "${{ github.event.discussion.title }}" "run:" path:.github/workflows'),
    8:  ("Discussion body in run",
         '"discussion" "${{ github.event.discussion.body }}" "run:" path:.github/workflows'),
    9:  ("Review body in run",
         '"pull_request_review" "${{ github.event.review.body }}" "run:" path:.github/workflows'),
    10: ("Review comment body in run",
         '"pull_request_review_comment" "${{ github.event.comment.body }}" "run:" path:.github/workflows'),
    11: ("toJSON(issue) in run",
         '"toJSON(github.event.issue)" "run:" path:.github/workflows'),
    12: ("toJSON(pull_request) in run",
         '"toJSON(github.event.pull_request)" "run:" path:.github/workflows'),
    13: ("toJSON(event) in run",
         '"toJSON(github.event)" "run:" path:.github/workflows'),
    14: ("toJSON(comment) in run",
         '"toJSON(github.event.comment)" "run:" path:.github/workflows'),
    15: ("toJSON(review) in run",
         '"toJSON(github.event.review)" "run:" path:.github/workflows'),
    16: ("toJSON(discussion) in run",
         '"toJSON(github.event.discussion)" "run:" path:.github/workflows'),
    17: ("contains(comment.body) in run",
         '"contains(github.event.comment.body" "run:" path:.github/workflows'),
    18: ("contains(issue.title) in run",
         '"contains(github.event.issue.title" "run:" path:.github/workflows'),
    19: ("contains(issue.body) in run",
         '"contains(github.event.issue.body" "run:" path:.github/workflows'),
    20: ("contains(PR title) in run",
         '"contains(github.event.pull_request.title" "run:" path:.github/workflows'),
    21: ("contains(PR body) in run",
         '"contains(github.event.pull_request.body" "run:" path:.github/workflows'),
    22: ("startsWith(comment.body) in run",
         '"startsWith(github.event.comment.body" "run:" path:.github/workflows'),
    23: ("format() with PR title",
         '"format(" "github.event.pull_request.title" "run:" path:.github/workflows'),
    24: ("format() with issue title",
         '"format(" "github.event.issue.title" "run:" path:.github/workflows'),
    25: ("Label name in run",
         '"github.event.label.name" "run:" path:.github/workflows'),
    26: ("PR head repo description",
         '"github.event.pull_request.head.repo.description" "run:" path:.github/workflows'),
    27: ("PR head repo homepage",
         '"github.event.pull_request.head.repo.homepage" "run:" path:.github/workflows'),
    28: ("Head ref in run (PR non-target)",
         '"pull_request" "github.head_ref" "run:" path:.github/workflows -pull_request_target'),
    29: ("PR head.ref in run (PRT)",
         '"pull_request_target" "github.event.pull_request.head.ref" "run:" path:.github/workflows'),
    30: ("toJSON(steps) in run",
         '"toJSON(steps" "run:" path:.github/workflows'),
    31: ("github-script + issue title",
         '"github-script" "github.event.issue.title" "script" path:.github/workflows'),
    32: ("github-script + issue body",
         '"github-script" "github.event.issue.body" "script" path:.github/workflows'),
    33: ("github-script + PR title",
         '"github-script" "github.event.pull_request.title" "script" path:.github/workflows'),
    34: ("github-script + PR body",
         '"github-script" "github.event.pull_request.body" "script" path:.github/workflows'),
    35: ("github-script + comment body",
         '"github-script" "github.event.comment.body" "script" path:.github/workflows'),
    36: ("GITHUB_ENV + github.event (issues)",
         '"GITHUB_ENV" "github.event.issue" path:.github/workflows'),
    37: ("GITHUB_ENV + github.event (PR)",
         '"GITHUB_ENV" "github.event.pull_request" path:.github/workflows'),
    38: ("GITHUB_ENV + comment body",
         '"GITHUB_ENV" "github.event.comment.body" path:.github/workflows'),
    39: ("Step outputs + issue event",
         '"steps." "outputs" "github.event.issue" "run:" path:.github/workflows'),
    40: ("Step outputs + PR event",
         '"steps." "outputs" "github.event.pull_request" "run:" path:.github/workflows'),
    41: ("Step outputs + comment event",
         '"steps." "outputs" "github.event.comment" "run:" path:.github/workflows'),
    42: ("workflow_dispatch inputs in run",
         '"workflow_dispatch" "inputs." "${{" "run:" path:.github/workflows'),
    43: ("workflow_dispatch inputs in script",
         '"workflow_dispatch" "inputs." "${{" "script" path:.github/workflows'),
}

# ── Dangerous expression patterns ──────────────────────────────────
DANGEROUS_EXPRESSIONS = [
    # TIER 1: Direct field access
    r"\$\{\{\s*github\.event\.issue\.title\s*\}\}",
    r"\$\{\{\s*github\.event\.issue\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.title\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.comment\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.review\.body\s*\}\}",
    r"\$\{\{\s*github\.event\.discussion\.title\s*\}\}",
    r"\$\{\{\s*github\.event\.discussion\.body\s*\}\}",
    r"\$\{\{\s*github\.head_ref\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.head\.ref\s*\}\}",
    r"\$\{\{\s*github\.event\.pull_request\.head\.label\s*\}\}",
    r"\$\{\{\s*github\.event\.pages\[\d+\]\.page_name\s*\}\}",
    # TIER 2: Field inside complex expression
    r"\$\{\{.*?github\.event\.issue\.title.*?\}\}",
    r"\$\{\{.*?github\.event\.issue\.body.*?\}\}",
    r"\$\{\{.*?github\.event\.pull_request\.title.*?\}\}",
    r"\$\{\{.*?github\.event\.pull_request\.body.*?\}\}",
    r"\$\{\{.*?github\.event\.comment\.body.*?\}\}",
    r"\$\{\{.*?github\.event\.review\.body.*?\}\}",
    r"\$\{\{.*?github\.event\.discussion\.title.*?\}\}",
    r"\$\{\{.*?github\.event\.discussion\.body.*?\}\}",
    r"\$\{\{.*?github\.head_ref.*?\}\}",
    r"\$\{\{.*?github\.event\.pull_request\.head\.ref.*?\}\}",
    r"\$\{\{.*?github\.event\.pull_request\.head\.label.*?\}\}",
    # TIER 3: toJSON on parent objects
    r"\$\{\{.*?toJSON\(\s*github\.event\.issue\s*\).*?\}\}",
    r"\$\{\{.*?toJSON\(\s*github\.event\.pull_request\s*\).*?\}\}",
    r"\$\{\{.*?toJSON\(\s*github\.event\.comment\s*\).*?\}\}",
    r"\$\{\{.*?toJSON\(\s*github\.event\.review\s*\).*?\}\}",
    r"\$\{\{.*?toJSON\(\s*github\.event\.discussion\s*\).*?\}\}",
    r"\$\{\{.*?toJSON\(\s*github\.event\s*\).*?\}\}",
    # TIER 4: Less common fields
    r"\$\{\{.*?github\.event\.pull_request\.head\.repo\.description.*?\}\}",
    r"\$\{\{.*?github\.event\.pull_request\.head\.repo\.homepage.*?\}\}",
    r"\$\{\{.*?github\.event\.label\.name.*?\}\}",
    # TIER 5: workflow_dispatch inputs
    r"\$\{\{.*?github\.event\.inputs\.[\w-]+.*?\}\}",
    r"\$\{\{.*?inputs\.[\w-]+.*?\}\}",
]

COMPILED_DANGEROUS = [re.compile(p) for p in DANGEROUS_EXPRESSIONS]

# ── GITHUB_ENV injection pattern ───────────────────────────────────
ENV_INJECT_PAT = re.compile(r'>>\s*"?\$GITHUB_ENV"?|>>\s*"?\$GITHUB_PATH"?')

# ── Expression classification sets ─────────────────────────────────
FULL_CONTROL = {
    'github.event.issue.title', 'github.event.issue.body',
    'github.event.comment.body', 'github.event.pull_request.title',
    'github.event.pull_request.body', 'github.event.review.body',
    'github.event.discussion.title', 'github.event.discussion.body',
    'github.event.pull_request.head.repo.description',
    'github.event.pull_request.head.repo.homepage',
}

PARENT_FULL_CONTROL = {
    'github.event.issue', 'github.event.pull_request',
    'github.event.comment', 'github.event.review',
    'github.event.discussion', 'github.event',
}

LIMITED_CONTROL = {
    'github.head_ref', 'github.event.pull_request.head.ref',
    'github.event.pull_request.head.label', 'github.event.label.name',
    'github.event.pull_request.head.repo.full_name',
    'github.event.pull_request.base.ref',
}

NO_CONTROL = {
    'github.event.issue.number', 'github.event.pull_request.number',
    'github.event.issue.html_url', 'github.event.pull_request.html_url',
    'github.event.issue.url', 'github.event.pull_request.url',
    'github.event.issue.comments_url', 'github.event.issue.events_url',
    'github.event.issue.labels_url', 'github.event.issue.repository_url',
    'github.event.pull_request.comments_url', 'github.event.pull_request.commits_url',
    'github.event.pull_request.diff_url', 'github.event.pull_request.patch_url',
    'github.event.pull_request.issue_url', 'github.event.pull_request.review_comments_url',
    'github.event.pull_request.statuses_url', 'github.event.pull_request.review_comment_url',
    'github.event.issue.pull_request',
    'github.event.issue.pull_request.url',
    'github.event.issue.pull_request.html_url',
    'github.event.issue.pull_request.diff_url',
    'github.event.issue.pull_request.patch_url',
    'github.event.issue.user.login', 'github.event.pull_request.user.login',
    'github.event.issue.user.html_url', 'github.event.issue.user.avatar_url',
    'github.event.comment.user.login', 'github.event.review.user.login',
    'github.event.comment.id', 'github.event.comment.node_id',
    'github.event.comment.user.html_url', 'github.event.comment.user.url',
    'github.event.comment.user.id', 'github.event.comment.user.avatar_url',
    'github.event.comment.author_association',
    'github.event.comment.created_at', 'github.event.comment.updated_at',
    'github.event.comment.html_url', 'github.event.comment.url',
    'github.event.comment.issue_url',
    'github.event.issue.id', 'github.event.issue.node_id',
    'github.event.pull_request.id', 'github.event.pull_request.node_id',
    'github.event.pull_request.merged_by.login',
    'github.repository', 'github.repository_owner',
    'github.actor', 'github.triggering_actor',
    'github.ref', 'github.ref_name', 'github.base_ref',
    'github.sha', 'github.run_id', 'github.run_number', 'github.event_name',
    'github.event.action', 'github.event.number',
    'github.event.pull_request.head.sha', 'github.event.pull_request.base.sha',
    'github.event.pull_request.merge_commit_sha',
    'github.event.pull_request.merged',
    'github.event.pull_request.draft',
    'github.event.pull_request.state',
    'github.event.pull_request.author_association',
    'github.event.pull_request.base.repo.full_name',
    'github.event.pull_request.base.repo.html_url',
    'github.event.pull_request.base.repo.url',
    'github.event.pull_request.labels',
    'github.event.pull_request.additions', 'github.event.pull_request.deletions',
    'github.event.pull_request.changed_files',
    'github.event.pull_request.commits',
    'github.event.pull_request.user.avatar_url',
    'github.event.pull_request.user.html_url',
    'github.event.pull_request.user.url',
    'github.event.pull_request.head.repo.url',
    'github.event.pull_request.head.repo.html_url',
    'github.event.pull_request.head.repo.owner.login',
    'github.event.pull_request.head.repo.owner.html_url',
    'github.event.pull_request.head.repo.owner.url',
    'github.event.issue.state', 'github.event.issue.locked',
    'github.event.issue.labels',
    'github.event.before', 'github.event.after',
    'github.event.repository.full_name', 'github.event.repository.name',
    'github.event.repository.html_url', 'github.event.repository.url',
    'github.event.repository.is_template',
    'github.event.sender.login', 'github.event.sender.id',
    'github.event.sender.html_url', 'github.event.sender.url',
    'github.workspace', 'github.event.compare',
    'github.event.discussion.id', 'github.event.discussion.node_id',
    'github.event.discussion.number', 'github.event.discussion.html_url',
    'github.event.discussion.url', 'github.event.discussion.state',
    'github.event.discussion.locked', 'github.event.discussion.comments',
    'github.event.discussion.created_at', 'github.event.discussion.updated_at',
    'github.event.discussion.author_association',
    'github.event.discussion.user.login', 'github.event.discussion.user.id',
    'github.event.discussion.category.name', 'github.event.discussion.category.id',
    'github.event.discussion.category.slug',
    'github.event.pull_request.created_at', 'github.event.pull_request.updated_at',
    'github.event.pull_request.closed_at', 'github.event.pull_request.merged_at',
    'github.event.issue.created_at', 'github.event.issue.updated_at',
    'github.event.issue.closed_at', 'github.event.issue.author_association',
    'github.workflow', 'github.workflow_ref', 'github.job', 'github.action',
    'github.server_url', 'github.api_url', 'github.graphql_url',
    'github.event.release.id', 'github.event.release.node_id',
    'github.event.release.html_url', 'github.event.release.url',
    'github.event.release.tag_name', 'github.event.release.target_commitish',
    'github.event.release.created_at', 'github.event.release.published_at',
}

NO_CONTROL_PREFIXES = (
    'github.event.repository.owner.',
    'github.event.organization.',
    'github.event.sender.',
    'github.event.installation.',
    'github.event.enterprise.',
)

EXPR_TRIGGERS = {
    'github.event.issue.title': ['issues', 'issue_comment'],
    'github.event.issue.body': ['issues', 'issue_comment'],
    'github.event.issue.user.login': ['issues', 'issue_comment'],
    'github.event.issue.html_url': ['issues', 'issue_comment'],
    'github.event.issue.number': ['issues', 'issue_comment'],
    'github.event.comment.body': ['issue_comment', 'pull_request_review_comment'],
    'github.event.pull_request.title': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.body': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.head.ref': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.head.label': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.head.repo.description': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.head.repo.homepage': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.user.login': ['pull_request', 'pull_request_target'],
    'github.event.pull_request.number': ['pull_request', 'pull_request_target'],
    'github.event.review.body': ['pull_request_review'],
    'github.head_ref': ['pull_request', 'pull_request_target'],
    'github.event.discussion.title': ['discussion', 'discussion_comment'],
    'github.event.discussion.body': ['discussion', 'discussion_comment'],
    'github.event.label.name': ['issues', 'pull_request', 'pull_request_target'],
    'github.event.pages': ['gollum'],
    'github.event.inputs': ['workflow_dispatch'],
    'inputs.': ['workflow_dispatch', 'workflow_call'],
}

OPEN_TYPES = {
    'issues': {'opened', 'edited', 'reopened', 'transferred', 'deleted'},
    'issue_comment': {'created', 'edited'},
    'pull_request_target': {'opened', 'synchronize', 'reopened', 'edited'},
    'pull_request_review': {'submitted', 'edited'},
    'discussion': {'created', 'edited'},
    'discussion_comment': {'created', 'edited'},
}

RESTRICTED_TYPES = {
    'issues': {'labeled', 'unlabeled', 'assigned', 'unassigned', 'milestoned',
               'demilestoned', 'closed', 'pinned'},
    'pull_request_target': {'closed', 'labeled', 'unlabeled', 'review_requested', 'assigned'},
}

INTERNAL_TRIGGERS = {
    'push', 'workflow_dispatch', 'schedule', 'release', 'deployment',
    'create', 'delete', 'fork', 'member', 'page_build', 'public',
    'watch', 'status',
}

DISABLE_PATS = [
    re.compile(r'^\s*if:\s*false\s*$', re.I),
    re.compile(r'^\s*if:\s*\$\{\{\s*false\s*\}\}', re.I),
    re.compile(r'^\s*if:\s*\$\{\{\s*always\(\)\s*&&\s*false', re.I),
    re.compile(r'^\s*if:\s*\$\{\{\s*true\s*&&\s*false', re.I),
    re.compile(r'^\s*if:\s*\$\{\{\s*false\s*&&', re.I),
]

AUTH_PATS = [
    re.compile(r"author_association\s*(==|!=)\s*'[A-Z_]+'", re.I),
    re.compile(r'get-user-teams-membership', re.I),
    re.compile(r'check-user-membership', re.I),
    re.compile(r"github\.actor\s*==\s*'[^']+'"),
    re.compile(r"github\.triggering_actor\s*==\s*'[^']+'"),
    re.compile(r'slash-command-dispatch', re.I),
    re.compile(r"github\.repository_owner\s*==\s*'[^']+'"),
    re.compile(r"github\.repository\s*==\s*'[^/]+/[^']+'"),
    re.compile(r"contains\(\s*'[^']*'\s*,\s*github\.(actor|triggering_actor)"),
]

OPENNESS_DESC = {
    'OPEN': 'Anyone — {trigger} is open to all GitHub users',
    'RESTRICTED': 'Limited — {trigger} requires specific permissions (label, assign, etc.)',
    'PR_FORK': 'Fork authors — pull_request from forks (limited secret access)',
    'INTERNAL': 'Internal only — {trigger} requires repo write access',
    'UNKNOWN_CALLER': 'Unknown — reusable workflow (workflow_call), depends on caller',
    'DISPATCH': 'Repo collaborators — workflow_dispatch requires write access',
}

SKIP_EXTENSIONS = {'.disabled', '.bak', '.off', '.example', '.tmpl', '.sample', '.txt', '.md'}

CONTROL_DESC = {
    'FULL_CONTROL': (
        'attacker-controlled',
        'Any GitHub user can set this value to arbitrary content '
        '(e.g. issue title, PR body, comment text)'),
    'LIMITED_CONTROL': (
        'limited-control',
        'Attacker can influence this value but with character restrictions '
        '(e.g. branch names cannot contain spaces or most special chars)'),
    'DISPATCH_INPUT': (
        'dispatch-input',
        'Only repo collaborators with write access can set this value '
        'via workflow_dispatch — not open to the public'),
    'NO_CONTROL': (
        'not-controlled',
        'Attacker cannot control this value '
        '(e.g. issue number, repo name, actor username)'),
    'UNKNOWN': (
        'unknown-control',
        'Could not determine attacker control level — manual review needed'),
}

SIZE_RANGES = [(1, 1000), (1001, 4000), (4001, 16000), (16001, None)]
MAX_RESULTS = 1000
MIN_SPLIT_SIZE = 50


def ctrl_label(level: str) -> str:
    """Short label for control level."""
    return CONTROL_DESC.get(level, (level, ''))[0]


def ctrl_explain(level: str) -> str:
    """Full explanation for control level."""
    return CONTROL_DESC.get(level, ('', 'Unknown control level'))[1]
