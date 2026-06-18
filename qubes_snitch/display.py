# Display-safe string helpers for terminal, notifications, and syslog
# Policy validation stays elsewhere; this module only prevents rendered text from spoofing UI/log rows

import unicodedata


MAX_DISPLAY_TEXT = 160


def safe_text(value, *, limit=MAX_DISPLAY_TEXT):
    # Remote DNS/PTR text can contain terminal controls, so render controls as spaces before UI/log output
    text = str(value)
    cleaned = []
    for char in text:
        category = unicodedata.category(char)
        if char in "\r\n\t" or char == "\x1b" or category.startswith("C"):
            cleaned.append(" ")
        else:
            cleaned.append(char)
    compact = " ".join("".join(cleaned).split())
    if len(compact) > limit:
        return compact[: limit - 1] + "…"
    return compact
