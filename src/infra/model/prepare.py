import re
import math
from urllib.parse import urlparse
from collections import Counter

def extract_url_features(url):
    """
    Extract all necessary features from a URL for malicious detection.

    Parameters:
    url (str): The URL to analyze

    Returns:
    dict: Dictionary containing all features needed for prediction
    """

    # Parse the URL
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # Basic URL metrics
    url_len = len(url)

    # Count digits and letters
    digits = sum(1 for char in url if char.isdigit())
    letters = sum(1 for char in url if char.isalpha())

    # Domain n-gram entropy (using 3-grams as example)
    domain_cleaned = re.sub(r'[^a-zA-Z0-9]', '', domain)
    domain_ngram_entropy = calculate_ngram_entropy(domain_cleaned, n=3)

    # Path features
    path_parts = [p for p in path.split('/') if p]
    path_depth = len(path_parts)
    path_entropy = calculate_string_entropy(path)

    # Character ratios
    consonants = sum(1 for char in url.lower() if char.isalpha() and char not in 'aeiou')
    vowels = sum(1 for char in url.lower() if char.isalpha() and char in 'aeiou')
    total_chars = len(url)

    consonant_ratio = consonants / total_chars if total_chars > 0 else 0
    vowel_ratio = vowels / total_chars if total_chars > 0 else 0
    digit_ratio = digits / total_chars if total_chars > 0 else 0

    # Token-based features
    tokens = re.split(r'[/\-_.?=&]', url)
    tokens = [t for t in tokens if t]  # Remove empty tokens

    avg_token_length = sum(len(token) for token in tokens) / len(tokens) if tokens else 0
    token_count = len(tokens)

    # Return all features as dictionary
    features = {
        'url_len': url_len,
        'digits': digits,
        'letters': letters,
        'domain_ngram_entropy': domain_ngram_entropy,
        'path_depth': path_depth,
        'path_entropy': path_entropy,
        'consonant_ratio': consonant_ratio,
        'vowel_ratio': vowel_ratio,
        'digit_ratio': digit_ratio,
        'avg_token_length': avg_token_length,
        'token_count': token_count
    }

    return features


def calculate_string_entropy(string):
    """
    Calculate Shannon entropy of a string.

    Parameters:
    string (str): Input string

    Returns:
    float: Shannon entropy value
    """
    if not string:
        return 0.0

    # Count character frequencies
    char_counts = Counter(string)
    length = len(string)

    # Calculate entropy
    entropy = 0
    for count in char_counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def calculate_ngram_entropy(string, n=3):
    """
    Calculate n-gram entropy of a string.

    Parameters:
    string (str): Input string
    n (int): n-gram size

    Returns:
    float: n-gram entropy value
    """
    if not string or len(string) < n:
        return 0.0

    # Generate n-grams
    ngrams = [string[i:i + n] for i in range(len(string) - n + 1)]

    # Calculate frequency distribution
    ngram_counts = Counter(ngrams)
    total_ngrams = len(ngrams)

    # Calculate entropy
    entropy = 0
    for count in ngram_counts.values():
        probability = count / total_ngrams
        entropy -= probability * math.log2(probability)

    return entropy