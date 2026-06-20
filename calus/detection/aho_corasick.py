"""
calus.detection.aho_corasick
============================
Real linear-time multi-literal scanner for the Tier-1 pre-filter. Replaces the
chunked-alternation approximation: one O(input) pass finds every literal anchor
present, regardless of how many anchors are registered. Pure Python, no deps,
cannot ReDoS-hang (no backtracking).
"""
from __future__ import annotations
from collections import deque

class AhoCorasick:
    def __init__(self):
        self.goto = [{}]            # trie transitions
        self.fail = [0]
        self.out = [set()]          # node -> set of payload keys ending here

    def add(self, word, payload):
        node = 0
        for ch in word:
            nxt = self.goto[node].get(ch)
            if nxt is None:
                nxt = len(self.goto)
                self.goto.append({}); self.fail.append(0); self.out.append(set())
                self.goto[node][ch] = nxt
            node = nxt
        self.out[node].add(payload)

    def build(self):
        q = deque()
        for ch, nxt in self.goto[0].items():
            self.fail[nxt] = 0; q.append(nxt)
        while q:
            r = q.popleft()
            for ch, u in self.goto[r].items():
                q.append(u)
                f = self.fail[r]
                while f and ch not in self.goto[f]:
                    f = self.fail[f]
                self.fail[u] = self.goto[f].get(ch, 0) if f or ch in self.goto[0] else 0
                self.out[u] |= self.out[self.fail[u]]
        return self

    def search(self, text):
        """Return the set of payloads whose literal occurs in text."""
        node = 0; found = set()
        for ch in text:
            while node and ch not in self.goto[node]:
                node = self.fail[node]
            node = self.goto[node].get(ch, 0)
            if self.out[node]:
                found |= self.out[node]
        return found
