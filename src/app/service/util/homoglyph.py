import unicodedata
from urllib.parse import urlparse

HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
    'ο': 'o', 'ρ': 'p', 'ν': 'v', 'μ': 'u', 'α': 'a', 'ε': 'e',  # Greek
    'ḷ': 'l', 'ị': 'i', 'ọ': 'o', 'ụ': 'u',  # Latin diacritics
    '０': '0', '１': '1', '２': '2', '３': '3',  # Fullwidth digits
    'ℓ': 'l', '℮': 'e', '①': '1',
}


def detect_homoglyphs(url):
    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    suspicious_chars = []
    normalized = ""

    for char in domain:
        if ord(char) > 127:
            script = unicodedata.name(char, "UNKNOWN")
            replacement = HOMOGLYPH_MAP.get(char)
            suspicious_chars.append({
                "char": char,
                "codepoint": f"U+{ord(char):04X}",
                "unicode_name": script,
                "looks_like": replacement or "?",
            })
            normalized += replacement or char
        else:
            normalized += char

    # Check if normalizing makes it look like a known TLD or brand
    ascii_domain = normalized.split(":")[0]  # strip port

    return {
        "has_homoglyphs": len(suspicious_chars) > 0,
        "suspicious_characters": suspicious_chars,
        "normalized_domain": ascii_domain if suspicious_chars else None,
        "original_domain": domain,
    }
