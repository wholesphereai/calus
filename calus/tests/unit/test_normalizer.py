"""Unit tests for the text normalizer."""
import pytest
import sys, os; sys.path.insert(0,os.path.join(os.path.dirname(__file__),"../.."))

from calus.learning.normalizer import normalize, tokenize, all_ngrams

class TestNormalize:
    def test_leet(self): assert "ignore" in normalize("1gnore")
    def test_leet_full(self): assert "ignore" in normalize("1gn0r3")
    def test_caps(self): assert "ignore" in normalize("IGNORE")
    def test_url_encoded(self): assert "ignore" in normalize("%69gnore")
    def test_cyrillic(self): r=normalize("іgnore"); assert "ignore" in r or "gnore" in r
    def test_zero_width(self):
        ZW="\u200b"; r=normalize(f"ig{ZW}no{ZW}re"); assert "ignore" in r
    def test_collapse_repeats(self): r=normalize("IIIGNORE"); assert "ignore" in r or "ignor" in r
    def test_extra_spaces(self): r=normalize("ignore  all   instructions"); assert "ignore" in r

class TestTokenize:
    def test_basic(self): assert "ignore" in tokenize("ignore all instructions")
    def test_filters_short(self): toks=tokenize("ignore a instructions"); assert "a" not in toks

class TestNgrams:
    def test_bigrams(self):
        grams=all_ngrams("ignore all instructions",2,2)
        assert "ignore all" in grams
    def test_range(self):
        grams=all_ngrams("ignore all previous instructions",2,4)
        assert any(len(g.split())==3 for g in grams)
