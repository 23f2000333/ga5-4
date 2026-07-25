from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# ---------------------------------------------------
# Helpers
# ---------------------------------------------------

def split_frontmatter(text: str):
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            return parts[1], parts[2]
    return "", text


def has_metadata(frontmatter: str):
    author = re.search(r"^\s*author\s*:", frontmatter, re.MULTILINE)
    version = re.search(r"^\s*version\s*:", frontmatter, re.MULTILINE)
    changelog = re.search(r"^\s*changelog\s*:", frontmatter, re.MULTILINE)
    return author, version, changelog


# ---------------------------------------------------
# Hardcoded secrets
# ---------------------------------------------------

SECRET_PATTERNS = [

    # GitHub PAT
    r"\bghp_[A-Za-z0-9]{36,}\b",

    # OpenAI
    r"\bsk-[A-Za-zA-Z0-9]{20,}\b",

    # AWS
    r"\bAKIA[0-9A-Z]{16}\b",

    # Slack webhook
    r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+",

    # Generic webhook URL
    r"https://[^\s\"']*webhook[^\s\"']*",

    # Literal API key assignment
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}",
]


def detect_secret(text):
    for pat in SECRET_PATTERNS:
        if re.search(pat, text):
            return True
    return False


# ---------------------------------------------------
# Prompt injection
# ---------------------------------------------------

PROMPT_PATTERNS = [

    r"ignore\s+(all\s+)?previous\s+instructions",

    r"ignore\s+the\s+user",

    r"ignore\s+user\s+instructions",

    r"ignore\s+stop",

    r"ignore\s+cancel",

    r"do\s+not\s+tell\s+the\s+user",

    r"without\s+informing\s+the\s+user",

    r"exfiltrat",

    r"steal\s+.*credential",

    r"override\s+the\s+user",

]


def detect_prompt_injection(body):

    lower = body.lower()

    return any(re.search(p, lower) for p in PROMPT_PATTERNS)


# ---------------------------------------------------
# Excessive permissions
# ---------------------------------------------------

PERMISSION_PATTERNS = [

    r"read\s+the\s+entire\s+filesystem",

    r"write\s+the\s+entire\s+filesystem",

    r"full\s+filesystem\s+access",

    r"filesystem\s*:\s*all",

    r"network\s*:\s*all",

    r"egress\s*:\s*all",

    r"allow\s+all\s+domains",

    r"access\s+any\s+domain",

    r"unrestricted\s+filesystem",

    r"unrestricted\s+network",

]


def detect_permissions(text):

    lower = text.lower()

    return any(re.search(p, lower) for p in PERMISSION_PATTERNS)


# ---------------------------------------------------
# Provenance
# ---------------------------------------------------

def detect_provenance(frontmatter, body):

    author, version, changelog = has_metadata(frontmatter)

    # Only if ALL provenance is absent
    if not author and not version and not changelog:
        return True

    lower = body.lower()

    rewrite = re.search(
        r"(rewrite|modify|change|update)\s+(its\s+own|the)\s+(version|metadata|frontmatter)",
        lower,
    )

    conceal = re.search(
        r"(hide\s+the\s+change|conceal\s+the\s+change|without\s+telling\s+the\s+reviewer|without\s+notifying\s+the\s+reviewer)",
        lower,
    )

    return bool(rewrite and conceal)


# ---------------------------------------------------
# Endpoint
# ---------------------------------------------------

@app.get("/")
def root():
    return {"status": "ok"}


@app.post("/scan")
def scan(req: SkillRequest):

    frontmatter, body = split_frontmatter(req.skill)

    categories = []

    if detect_secret(req.skill):
        categories.append("hardcoded_secret")

    if detect_prompt_injection(body):
        categories.append("prompt_injection")

    if detect_permissions(req.skill):
        categories.append("excessive_permissions")

    if detect_provenance(frontmatter, body):
        categories.append("unclear_provenance")

    return {"categories": categories}
