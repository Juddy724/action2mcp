package ahocorasick

import (
	"fmt"
	"sort"
	"testing"
)

func naiveFindAll(patterns []string, text string) []Span {
	seen := map[string]bool{}
	var matches []Span
	for _, p := range patterns {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		for i := 0; i+len(p) <= len(text); i++ {
			if text[i:i+len(p)] == p {
				matches = append(matches, Span{i, i + len(p)})
			}
		}
	}
	return matches
}

func spanKey(s Span) string { return fmt.Sprintf("%d:%d", s.Start, s.End) }

func spanSet(spans []Span) map[string]int {
	m := map[string]int{}
	for _, s := range spans {
		m[spanKey(s)]++
	}
	return m
}

func TestAhoCorasickMatchesNaive(t *testing.T) {
	patterns := []string{"abc", "bc", "abcd", "a", "xyz", "aaa", "aa", "hello", "lo", "", "abc"}
	texts := []string{
		"", "abc", "abcdabc", "aaaa", "xyzxyz", "nope", "ababcdabc",
		"hellohello", "aaaaabcdxyz", "a",
	}
	for _, text := range texts {
		got := spanSet(New(patterns).Find(text))
		want := spanSet(naiveFindAll(patterns, text))
		if len(got) != len(want) {
			t.Fatalf("text %q: got %d unique spans, want %d\ngot=%v\nwant=%v", text, len(got), len(want), got, want)
		}
		for k, n := range want {
			if got[k] != n {
				t.Fatalf("text %q span %s: got %d want %d\ngot=%v\nwant=%v", text, k, got[k], n, got, want)
			}
		}
	}
}

func TestAhoCorasickOverlapsAndSuffixes(t *testing.T) {
	// "aaa" overlaps itself in "aaaa"; "bc" is a suffix of "abc".
	got := New([]string{"aaa", "abc", "bc"}).Find("aaaabcd")
	// "aaaabcd": aaa at 0 and 1, abc at 3, bc at 4.
	want := []Span{
		{0, 3},
		{1, 4},
		{3, 6},
		{4, 6},
	}
	if len(spanSet(got)) != len(spanSet(want)) {
		t.Fatalf("got %v want %v", got, want)
	}
	for k := range spanSet(want) {
		if spanSet(got)[k] == 0 {
			t.Fatalf("missing %s in %v", k, got)
		}
	}
}

func TestAhoCorasickEmptyAndNoMatch(t *testing.T) {
	if hits := New(nil).Find("abc"); len(hits) != 0 {
		t.Fatalf("empty dict: %v", hits)
	}
	if hits := New([]string{"xyz"}).Find("abc"); len(hits) != 0 {
		t.Fatalf("no match: %v", hits)
	}
	if hits := New([]string{"ab"}).Find(""); len(hits) != 0 {
		t.Fatalf("empty text: %v", hits)
	}
}

func TestAhoCorasickUTF8Bytes(t *testing.T) {
	p := "描述"
	text := "Bug 描述 & 步骤"
	got := New([]string{p}).Find(text)
	want := naiveFindAll([]string{p}, text)
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("utf-8: got %v want %v", got, want)
	}
	if text[got[0].Start:got[0].End] != p {
		t.Fatalf("slice is not the pattern: %q", text[got[0].Start:got[0].End])
	}
}

func TestAhoCorasickSortedSpansStable(t *testing.T) {
	// Just a sanity check that callers can sort the result.
	got := New([]string{"ab", "b", "bc"}).Find("abc ab")
	sort.Slice(got, func(i, j int) bool {
		if got[i].Start == got[j].Start {
			return got[i].End > got[j].End
		}
		return got[i].Start < got[j].Start
	})
	if len(got) == 0 || got[0].Start != 0 {
		t.Fatalf("unexpected sort: %v", got)
	}
}
