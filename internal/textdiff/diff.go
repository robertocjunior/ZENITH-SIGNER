// Package textdiff computes a simple line-based diff for showing document changes.
package textdiff

import "strings"

// Op is a diff operation.
type Op struct {
	Kind byte // '=', '+', '-'
	Text string
}

// maxCells bounds the LCS table; beyond it the diff degrades to "all removed / all added".
const maxCells = 4_000_000

// Lines diffs a and b line by line using the longest common subsequence.
func Lines(a, b string) []Op {
	al := splitLines(a)
	bl := splitLines(b)

	// Trim common prefix/suffix to keep the table small.
	pre := 0
	for pre < len(al) && pre < len(bl) && al[pre] == bl[pre] {
		pre++
	}
	suf := 0
	for suf < len(al)-pre && suf < len(bl)-pre && al[len(al)-1-suf] == bl[len(bl)-1-suf] {
		suf++
	}

	var ops []Op
	for _, l := range al[:pre] {
		ops = append(ops, Op{'=', l})
	}
	ops = append(ops, lcs(al[pre:len(al)-suf], bl[pre:len(bl)-suf])...)
	for _, l := range al[len(al)-suf:] {
		ops = append(ops, Op{'=', l})
	}
	return ops
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

func lcs(a, b []string) []Op {
	n, m := len(a), len(b)
	if n == 0 && m == 0 {
		return nil
	}
	if n*m > maxCells {
		ops := make([]Op, 0, n+m)
		for _, l := range a {
			ops = append(ops, Op{'-', l})
		}
		for _, l := range b {
			ops = append(ops, Op{'+', l})
		}
		return ops
	}

	t := make([][]int32, n+1)
	for i := range t {
		t[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				t[i][j] = t[i+1][j+1] + 1
			} else if t[i+1][j] >= t[i][j+1] {
				t[i][j] = t[i+1][j]
			} else {
				t[i][j] = t[i][j+1]
			}
		}
	}

	ops := make([]Op, 0, n+m)
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, Op{'=', a[i]})
			i++
			j++
		case t[i+1][j] >= t[i][j+1]:
			ops = append(ops, Op{'-', a[i]})
			i++
		default:
			ops = append(ops, Op{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, Op{'-', a[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, Op{'+', b[j]})
	}
	return ops
}

// Stats counts added and removed lines.
func Stats(ops []Op) (added, removed int) {
	for _, o := range ops {
		switch o.Kind {
		case '+':
			added++
		case '-':
			removed++
		}
	}
	return
}
