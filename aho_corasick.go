package main

// Aho–Corasick multi-pattern matcher used by secret scrubbing.
// Matching is byte-wise, the same contract as strings.Index. After Build,
// Find reports every occurrence, including overlaps and suffix matches
// reached through failure links. There is no third-party dependency.
//
// Children are stored sparsely: a typical secret trie is a long chain
// with one outgoing edge per node, so a 256-wide pointer array would
// cost a couple of kilobytes per node and tens of megabytes for a few
// hundred cookie variants.
type ahoCorasick struct {
	root *acNode
}

type acEdge struct {
	b byte
	n *acNode
}

type acNode struct {
	next []acEdge
	fail *acNode
	// out holds the byte lengths of patterns that end at this node,
	// including those inherited from failure links. A node corresponds
	// to one path, so lengths at the same node are distinct.
	out []int
}

func (n *acNode) child(b byte) *acNode {
	for i := range n.next {
		if n.next[i].b == b {
			return n.next[i].n
		}
	}
	return nil
}

func (n *acNode) setChild(b byte, c *acNode) {
	for i := range n.next {
		if n.next[i].b == b {
			n.next[i].n = c
			return
		}
	}
	n.next = append(n.next, acEdge{b, c})
}

func newAhoCorasick(patterns []string) *ahoCorasick {
	root := &acNode{}
	seen := make(map[string]struct{}, len(patterns))
	for _, p := range patterns {
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		n := root
		for i := 0; i < len(p); i++ {
			b := p[i]
			c := n.child(b)
			if c == nil {
				c = &acNode{}
				n.setChild(b, c)
			}
			n = c
		}
		n.out = append(n.out, len(p))
	}
	// Failure links: BFS. Depth-1 nodes fail to root. Deeper nodes follow
	// the longest proper suffix that is still a trie prefix.
	q := make([]*acNode, 0, 64)
	for _, e := range root.next {
		e.n.fail = root
		q = append(q, e.n)
	}
	for len(q) > 0 {
		n := q[0]
		q = q[1:]
		for _, e := range n.next {
			c := e.n
			q = append(q, c)
			f := n.fail
			for f != nil && f.child(e.b) == nil {
				f = f.fail
			}
			if f != nil {
				if next := f.child(e.b); next != nil {
					c.fail = next
				} else {
					c.fail = root
				}
			} else {
				c.fail = root
			}
			if len(c.fail.out) > 0 {
				// Copy: a shared backing array would be mutated if a later
				// node appends to a slice that aliases its fail output.
				merged := make([]int, len(c.out)+len(c.fail.out))
				copy(merged, c.out)
				copy(merged[len(c.out):], c.fail.out)
				c.out = merged
			}
		}
	}
	return &ahoCorasick{root: root}
}

func (m *ahoCorasick) find(text string) []approvalTextSpan {
	if m == nil || m.root == nil || text == "" {
		return nil
	}
	var matches []approvalTextSpan
	n := m.root
	for i := 0; i < len(text); i++ {
		b := text[i]
		for n != m.root && n.child(b) == nil {
			n = n.fail
			if n == nil {
				n = m.root
				break
			}
		}
		if c := n.child(b); c != nil {
			n = c
		}
		for _, L := range n.out {
			if L <= 0 || L > i+1 {
				continue
			}
			matches = append(matches, approvalTextSpan{i + 1 - L, i + 1})
		}
	}
	return matches
}
