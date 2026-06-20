"""
Pure-Python drop-in for the subset of `pyahocorasick` this package uses:
    A = Automaton(); A.add_word(key, value); A.make_automaton()
    for end_index, value in A.iter(text): ...
Used automatically when the C library `ahocorasick` is not installed, so Calus
has zero hard external dependencies. Install `pyahocorasick` for more speed.
"""
from collections import deque

class Automaton:
    def __init__(self):
        self._goto = [{}]
        self._fail = [0]
        self._out = [[]]          # node -> list of (key_len, value)
        self._built = False

    def add_word(self, key, value):
        if not key:
            return
        node = 0
        for ch in key:
            nxt = self._goto[node].get(ch)
            if nxt is None:
                nxt = len(self._goto)
                self._goto.append({}); self._fail.append(0); self._out.append([])
                self._goto[node][ch] = nxt
            node = nxt
        self._out[node].append((len(key), value))
        self._built = False

    def make_automaton(self):
        q = deque()
        for ch, nxt in self._goto[0].items():
            self._fail[nxt] = 0; q.append(nxt)
        while q:
            r = q.popleft()
            for ch, u in self._goto[r].items():
                q.append(u)
                f = self._fail[r]
                while f and ch not in self._goto[f]:
                    f = self._fail[f]
                self._fail[u] = self._goto[f].get(ch, 0)
                self._out[u] = self._out[u] + self._out[self._fail[u]]
        self._built = True

    def iter(self, text):
        if not self._built:
            self.make_automaton()
        node = 0
        for i, ch in enumerate(text):
            while node and ch not in self._goto[node]:
                node = self._fail[node]
            node = self._goto[node].get(ch, 0)
            for _klen, value in self._out[node]:
                yield i, value

    def __len__(self):
        return len(self._goto)
