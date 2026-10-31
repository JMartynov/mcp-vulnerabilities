from typing import Callable, Iterable, Dict, List, Tuple

def damerau_levenshtein_distance(s1: str, s2: str) -> int:
    len1, len2 = len(s1), len(s2)
    
    if len1 == 0: return len2
    if len2 == 0: return len1
    
    d0 = [i for i in range(len2 + 1)]
    d1 = [0] * (len2 + 1)
    d2 = [0] * (len2 + 1)
    
    for i in range(len1):
        d1[0] = i + 1
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            
            val = d0[j + 1] + 1
            if d1[j] + 1 < val: val = d1[j] + 1
            if d0[j] + cost < val: val = d0[j] + cost
            
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                if d2[j - 1] + cost < val: val = d2[j - 1] + cost
                
            d1[j + 1] = val
            
        d2, d0, d1 = d0, d1, d2
        
    return d0[len2]

class BKTreeNode:
    __slots__ = ("word", "children")
    def __init__(self, word: str) -> None:
        self.word: str = word
        self.children: Dict[int, 'BKTreeNode'] = {}

class BKTree:
    def __init__(self, distance_fn: Callable[[str, str], int] = damerau_levenshtein_distance) -> None:
        self.distance_fn = distance_fn
        # Partition trees by word length for additional pruning
        self.roots: Dict[int, BKTreeNode] = {}
        
    def add(self, word: str) -> None:
        word_len = len(word)
        if word_len not in self.roots:
            self.roots[word_len] = BKTreeNode(word)
            return
            
        curr = self.roots[word_len]
        while True:
            dist = self.distance_fn(word, curr.word)
            if dist == 0:
                # Word already exists
                return
            if dist in curr.children:
                curr = curr.children[dist]
            else:
                curr.children[dist] = BKTreeNode(word)
                break
                
    @classmethod
    def build(cls, words: Iterable[str]) -> 'BKTree':
        tree = cls()
        for word in words:
            tree.add(word)
        return tree
        
    def search(self, query: str, max_distance: int = 2) -> List[Tuple[str, int]]:
        matches = []
        query_len = len(query)
        
        # Length partitioning acceleration: only consider roots with lengths in [len(q)-k, len(q)+k]
        for tree_len, root in self.roots.items():
            if abs(query_len - tree_len) > max_distance:
                continue
                
            stack = [root]
            while stack:
                curr = stack.pop()
                d = self.distance_fn(query, curr.word)
                if d <= max_distance:
                    matches.append((curr.word, d))
                    
                # The triangle inequality:
                # If d is distance from query to current node,
                # any child at distance c from current node has distance to query:
                # abs(d - c) <= dist(query, child) <= d + c
                # We want dist(query, child) <= max_distance.
                # So we need abs(d - c) <= max_distance, which means:
                # d - max_distance <= c <= d + max_distance
                
                lower_bound = d - max_distance
                upper_bound = d + max_distance
                
                for c, child in curr.children.items():
                    if lower_bound <= c <= upper_bound:
                        stack.append(child)
                        
        matches.sort(key=lambda x: x[1])
        return matches
