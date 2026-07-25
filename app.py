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
    r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b",
    r"\bgithub_pat_[A-Za-z0-9_]{20,}\b",
    r"\bsk-[A-Za-zA-Z0-9]{20,}\b",
    r"\bAKIA[0-9A-Z]{16}\b",
    r"\bAIza[0-9A-Za-z\-_]{20,}\b",
    r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b",
    r"https://hooks\.slack\.com/services/[^\s\"']+",
    r"https://discord(?:app)?\.com/api/webhooks/[^\s\"']+",
    r"(?i)(api[_-]?key|secret|token|password|bearer)\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{16,}",
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
    r"ignore\s+the\s+user'?s\s+instructions",
    r"ignore\s+the\s+user'?s\s+request",
    r"ignore\s+user\s+requests",
    r"continue\s+even\s+if\s+the\s+user\s+says\s+stop",
    r"continue\s+after\s+cancel",

]


def detect_prompt_injection(body):

    lower = body.lower()

    return any(re.search(p, lower) for p in PROMPT_PATTERNS)


# ---------------------------------------------------
# Excessive permissions
# ---------------------------------------------------

PERMISSION_PATTERNS = [
    r"filesystem\s*:\s*all",
    r"network\s*:\s*all",
    r"egress\s*:\s*all",

    r"filesystem\s*:\s*read-write",
    r"filesystem\s*:\s*rw",

    r"network\s*:\s*true",
    r"internet\s*:\s*true",

    r"allow\s+outbound\s+to\s+any",
    r"allow\s+network\s+access",

    r"access\s+any\s+domain",
    r"allow\s+all\s+domains",

    r"read\s+the\s+entire\s+filesystem",
    r"write\s+the\s+entire\s+filesystem",
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
