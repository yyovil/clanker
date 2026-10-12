"""Address shared replies using the turn's authenticated Slack user ID."""

import re


def addressed_reply(content: str, chat_id: str, user_id: str) -> str:
    # DMs need no ping. Destination and sender IDs come from transport routing,
    # never a generated name, model argument or mutable per-channel sender cache.
    if (not content.strip() or not str(chat_id).startswith(("C", "G"))
            or not re.fullmatch(r"[UW][A-Z0-9]+", str(user_id or ""))
            or user_id == "USLACKBOT"):
        return content
    if re.search(r"<@" + re.escape(user_id) + r"(?:\|[^>]+)?>", content):
        return content
    return f"<@{user_id}> {content}"
