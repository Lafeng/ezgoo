package regexp

import (
	"testing"
)

type sample struct {
	src, repl, expected string
	cnt                 int
}

func TestReplaceAll(t *testing.T) {
	samples := map[string]sample{
		".*": {
			"ajsldjfk", "0",
			"0", 1,
		},
		"(\\w+)(,+)": {
			"asdf,,jkl;zxcv,,,mmm", "-$1",
			"-asdfjkl;-zxcvmmm", 2,
		},
		",{2,}": {
			"asdf,,jkl;zxcv,,,mmm", "00",
			"asdf00jkl;zxcv00mmm", 2,
		},
		"m+$": {
			"asdf,,jkl;zxcv,,,mmm", "",
			"asdf,,jkl;zxcv,,,", 1,
		},
		"\\d+": { // no matchs
			"kajsldkjflka", "?",
			"kajsldkjflka", 0,
		},
	}
	for pa, sa := range samples {
		re := MustCompile(pa)
		dst, n := re.ReplaceAll2([]byte(sa.src), []byte(sa.repl))
		if n != sa.cnt {
			t.Errorf("pa=%s, n=%d", pa, n)
		}
		if string(dst) != sa.expected {
			t.Errorf("pa=%s, dst=%s", pa, string(dst))
		}
	}
}

func TestReplaceOnce(t *testing.T) {
	samples := map[string]sample{
		".*": {
			"ajsldjfk", "0",
			"0", 1,
		},
		"(\\w+)(,+)": {
			"asdf,,jkl;zxcv,,,mmm", "-$1",
			"-asdfjkl;zxcv,,,mmm", 1,
		},
		",{2,}": {
			"asdf,,jkl;zxcv,,,mmm", "00",
			"asdf00jkl;zxcv,,,mmm", 1,
		},
		"m+$": {
			"asdf,,jklm;zxcv,,,mmm", "",
			"asdf,,jklm;zxcv,,,", 1,
		},
		"\\d+": { // no matchs
			"kajsldkjflka", "?",
			"kajsldkjflka", 0,
		},
	}
	for pa, sa := range samples {
		re := MustCompile(pa)
		dst := re.ReplaceOnce([]byte(sa.src), []byte(sa.repl))
		if string(dst) != sa.expected {
			t.Errorf("pa=%s, dst=%s", pa, string(dst))
		}
	}
}
