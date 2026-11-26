def slug(s: str) -> str:
    return "-".join(s.lower().split())


def word_count(s: str) -> int:
    return len(s.split())
