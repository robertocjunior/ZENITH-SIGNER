package textdiff

import "testing"

func TestLines(t *testing.T) {
	ops := Lines("a\nb\nc\nd", "a\nB\nc\nd\ne")
	var got string
	for _, o := range ops {
		got += string(o.Kind) + o.Text + "|"
	}
	want := "=a|-b|+B|=c|=d|+e|"
	if got != want {
		t.Errorf("got %s want %s", got, want)
	}
	added, removed := Stats(ops)
	if added != 2 || removed != 1 {
		t.Errorf("stats: +%d -%d", added, removed)
	}
	if len(Lines("", "")) != 0 {
		t.Errorf("empty diff expected")
	}
	if a, r := Stats(Lines("", "x\ny")); a != 2 || r != 0 {
		t.Errorf("all-added diff wrong: +%d -%d", a, r)
	}
}
