import pytest
import time
import random
from mcp_vulnerabilities.analyzers.typosquat.bktree import BKTree, damerau_levenshtein_distance

def test_bktree_empty_and_single_node():
    tree = BKTree()
    assert len(tree.roots) == 0
    assert tree.search("hello") == []
    
    tree.insert("hello")
    assert len(tree.roots) == 1
    assert tree.search("hello") == [("hello", 0)]
    assert tree.search("world") == []

def test_bktree_exact_match():
    words = ["alpha", "beta", "gamma", "delta", "epsilon"]
    tree = BKTree.build(words)
    
    for word in words:
        matches = tree.search(word, max_distance=0)
        assert len(matches) == 1
        assert matches[0] == (word, 0)

def test_bktree_triangle_pruning_equivalence():
    corpus = ["apple", "banana", "cherry", "date", "elderberry", "fig", "grape"]
    tree = BKTree.build(corpus)
    
    queries = ["aple", "banan", "cheery", "figs"]
        
    for query in queries:
        k = 2
        expected = []
        for word in corpus:
            dist = damerau_levenshtein_distance(query, word)
            if dist <= k:
                expected.append((word, dist))
        
        expected.sort(key=lambda x: (x[1], x[0]))
        
        actual = tree.search(query, max_distance=k)
        actual.sort(key=lambda x: (x[1], x[0]))
        
        assert len(actual) == len(expected)
        assert set(actual) == set(expected)
