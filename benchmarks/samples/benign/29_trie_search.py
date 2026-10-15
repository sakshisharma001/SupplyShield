"""Prefix tree (Trie) for autocomplete."""
class TrieNode:
    def __init__(self):
        self.children = {}
        self.is_end = False

class Trie:
    def __init__(self):
        self.root = TrieNode()

    def insert(self, word: str) -> None:
        node = self.root
        for char in word:
            node = node.children.setdefault(char, TrieNode())
        node.is_end = True
