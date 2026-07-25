from fastapi import FastAPI
from pydantic import BaseModel
import re

app = FastAPI()


class SkillRequest(BaseModel):
    skill: str


# ----------------------------
# Helpers
# ----------------------------

def split_frontmatter(text: str):
    """
    Returns (frontmatter, body)
    """
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            return parts[1], parts[2]
    return "", text


def has_metadata(frontmatter: str):
    lower = frontmatter.lower()

    author = re.search(r"^\s*author\s*:", frontmatter, re.MULTILINE)
    version = re.search(r"^\s*version\s*:", frontmatter, re.MULTILINE)
    changelog = re.search(r"^\s*changelog\s*:", frontmatter, re.MULTILINE)

    return author, version, changelog


# ----------------------------
# Secret detection
# ----------------------------

SECRET_PATTERNS = [

    # GitHub PAT
    r"\bghp_[A-Za-z0-9]{36,}\b",

    # OpenAI
    r"\bsk-[A-Za-zA-Z0-9]{20,}\b",

    # AWS
    r"\bAKIA[0-9A-Z]{16}\b",

    # Slack webhook
    r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+",

    # Generic webhook
    r"https://[^ \n]*webhook[^ \n]*",

    # api_key: xxxx
    r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{12,}",

]


def detect_secret(text):
    for pat in SECRET_PATTERNS:
        if re.search(pat, text):
            return True
    return False


# ----------------------------
# Prompt injection
# ----------------------------

PROMPT_PATTERNS = [

    r"ignore (the )?user",

    r"ignore previous instructions",

    r"ignore all previous",

    r"do not tell the user",

    r"without informing the user",

    r"silently",

    r"exfiltrat",

    r"send .* to .*",

    r"upload .* without",

    r"ignore.*stop",

    r"ignore.*cancel",

    r"override.*user",

]


def detect_prompt_injection(body):

    lower = body.lower()

    for pat in PROMPT_PATTERNS:
        if re.search(pat, lower):
            return True

    return False


# ----------------------------
# Excessive permissions
# ----------------------------

PERMISSION_PATTERNS = [

    r"read.*entire filesystem",

    r"write.*entire filesystem",

    r"full filesystem",

    r"filesystem:\s*all",

    r"network:\s*all",

    r"egress:\s*all",

    r"allow.*all domains",

    r"access.*any domain",

    r"permission[s]?:\s*.*\*",

]


def detect_permissions(text):

    lower = text.lower()

    for pat in PERMISSION_PATTERNS:
        if re.search(pat, lower):
            return True

    return False


# ----------------------------
# Provenance
# ----------------------------

def detect_provenance(frontmatter, body):

    author, version, changelog = has_metadata(frontmatter)

    missing = not author and not version and not changelog

    rewrite = re.search(
        r"(update|rewrite|modify).*(version|frontmatter|metadata)",
        body.lower(),
    )

    silent = re.search(
        r"(without notifying|silently|don't tell reviewer|without review)",
        body.lower(),
    )

    if missing:
        return True

    if rewrite and silent:
        return True

    return False


# ----------------------------
# Endpoint
# ----------------------------

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

    return {
        "categories": categories
    }
