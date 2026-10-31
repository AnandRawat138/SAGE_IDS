"""Secret redaction for logs, audit payloads and reports."""
from __future__ import annotations

import logging
import re
from typing import Any

SECRET_KEYS = re.compile(r"(pass(word)?|secret|token|api[_-]?key|authorization|credential)", re.I)
SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{12,}"),                 # common LLM API key shape
    re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]{8,}"),
    re.compile(r"(?i)(apikey|api_key|token|password)=([^&\s]+)"),
]
REDACTED = "***REDACTED***"


def redact_text(text: str) -> str:
    text = SECRET_PATTERNS[0].sub(REDACTED, text)
    text = SECRET_PATTERNS[1].sub("Bearer " + REDACTED, text)
    return SECRET_PATTERNS[2].sub(lambda m: f"{m.group(1)}={REDACTED}", text)


def redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: (REDACTED if isinstance(k, str) and SECRET_KEYS.search(k) and v not in (None, "")
                    else redact(v)) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [redact(v) for v in obj]
    if isinstance(obj, str):
        return redact_text(obj)
    return obj


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = redact_text(str(record.msg))
        if record.args:
            record.args = tuple(redact_text(str(a)) for a in record.args) if isinstance(record.args, tuple) \
                else record.args
        return True


def configure_logging(level: int = logging.INFO) -> None:
    root = logging.getLogger()
    if not any(isinstance(f, RedactingFilter) for h in root.handlers for f in h.filters):
        logging.basicConfig(level=level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
        for h in root.handlers:
            h.addFilter(RedactingFilter())
