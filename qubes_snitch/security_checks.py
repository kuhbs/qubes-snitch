# Small security predicates shared by config, DNS, PTR, and source parsing
# Keep these checks boring so every caller can enforce policy at its own input boundary


def has_non_ascii(value):
    # Bytes are checked before parsing; text is checked before storing, displaying, or trusting it
    if isinstance(value, bytes):
        return any(byte > 127 for byte in value)
    return not str(value).isascii()
