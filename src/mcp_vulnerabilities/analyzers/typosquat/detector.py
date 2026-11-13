from enum import Enum
import re
from typing import Optional, Set
import unicodedata
from dataclasses import dataclass

from .bktree import damerau_levenshtein_distance, BKTree

def check_keyboard_proximity(s1: str, s2: str) -> bool:
    # A simplified QWERTY adjacency map
    kb = {
        'q': 'w a s', 'w': 'q e a s d', 'e': 'w r s d f', 'r': 'e t d f g',
        't': 'r y f g h', 'y': 't u g h j', 'u': 'y i h j k', 'i': 'u o j k l',
        'o': 'i p k l', 'p': 'o l',
        'a': 'q w s z x', 's': 'q w e a d z x c', 'd': 'w e r s f x c v',
        'f': 'e r t d g c v b', 'g': 'r t y f h v b n', 'h': 't y u g j b n m',
        'j': 'y u i h k n m', 'k': 'u i o j l m', 'l': 'i o p k',
        'z': 'a s x', 'x': 'z a s d c', 'c': 'x s d f v', 'v': 'c d f g b',
        'b': 'v f g h n', 'n': 'b g h j m', 'm': 'n h j k'
    }

    if len(s1) != len(s2):
        return False

    diffs = 0
    diff_idx = -1
    for i in range(len(s1)):
        if s1[i] != s2[i]:
            diffs += 1
            diff_idx = i

    if diffs == 1:
        c1 = s1[diff_idx].lower()
        c2 = s2[diff_idx].lower()
        if c1 in kb and c2 in kb[c1].split():
            return True
    return False


class RiskTier(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    SUSPICIOUS = "SUSPICIOUS"
    AUTHENTIC = "AUTHENTIC"

@dataclass
class TyposquatResult:
    package_name: str
    canonical_name: Optional[str]
    risk_tier: RiskTier
    reason: str
    distance: int

def levenshtein_distance(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def normalize_confusables(text: str) -> str:
    """Normalize unicode confusables (homoglyphs) to basic Latin where possible."""
    # A simple but effective mapping for common Cyrillic/Greek to Latin look-alikes
    confusables = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
        'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
        'ο': 'o', 'ν': 'v'
    }
    res = []
    for char in text:
        if char in confusables:
            res.append(confusables[char])
        else:
            res.append(char)

    return unicodedata.normalize('NFKD', "".join(res)).encode('ascii', 'ignore').decode('ascii')


class TyposquatDetector:
    def __init__(self, corpus: Set[str]):
        self.corpus = corpus
        self.bktree = BKTree.build(self.corpus)

    def analyze(self, package_name: str) -> TyposquatResult:
        if package_name in self.corpus:
            return TyposquatResult(package_name, package_name, RiskTier.AUTHENTIC, "Exact match", 0)

        # 1. Homoglyph Detection
        normalized_name = normalize_confusables(package_name)
        if normalized_name != package_name:
            if normalized_name in self.corpus:
                return TyposquatResult(package_name, normalized_name, RiskTier.CRITICAL, "CRITICAL_HOMOGLYPH_ATTACK", 0)

            # Check distance against normalized
            matches = self.bktree.search(normalized_name, max_distance=2)
            if matches:
                best_match, min_dist = matches[0]
                return TyposquatResult(package_name, best_match, RiskTier.CRITICAL, "CRITICAL_HOMOGLYPH_ATTACK", min_dist)

        # 2. Permutation/Transposition Detection
        parts = re.split(r'[-/]', package_name)
        parts_sorted = sorted(parts)
        for canon in self.corpus:
            canon_parts = re.split(r'[-/]', canon)
            if sorted(canon_parts) == parts_sorted and parts != canon_parts:
                return TyposquatResult(package_name, canon, RiskTier.SUSPICIOUS, "SUSPICIOUS_NAMING_PERMUTATION", 0)


        # 2.5 Keyboard Proximity (Bit-Squatting)
        for canon in self.corpus:
            if check_keyboard_proximity(package_name, canon):
                return TyposquatResult(package_name, canon, RiskTier.HIGH, "HIGH_RISK_TYPOSQUAT (Keyboard Proximity)", 1)

        # 3. Levenshtein Distance (Typosquatting)
        if self.bktree:
            matches = self.bktree.search(package_name, max_distance=2)
            if matches:
                best_match, min_dist = matches[0]
                return TyposquatResult(package_name, best_match, RiskTier.HIGH, "HIGH_RISK_TYPOSQUAT", min_dist)
        else:
            # Fall back gracefully to direct comparison if tree is not built
            best_match = None
            min_dist = float('inf')
            for canon in self.corpus:
                d = damerau_levenshtein_distance(package_name, canon)
                if d <= 2 and d < min_dist:
                    min_dist = d
                    best_match = canon

            if best_match:
                return TyposquatResult(package_name, best_match, RiskTier.HIGH, "HIGH_RISK_TYPOSQUAT", min_dist)

        return TyposquatResult(package_name, None, RiskTier.AUTHENTIC, "No typosquat detected", 0)

