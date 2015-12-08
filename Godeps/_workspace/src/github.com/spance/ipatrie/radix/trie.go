package ipatrie

type Trie struct {
	lefts, rights, values []uint32
	size                  uint32
}

const (
	NULL          uint32 = 0xffFFffFF
	IPV4_HIGH_BIT uint32 = 0x80000000
)

func makeArray(size int) []uint32 {
	tmp := make([]uint32, size)
	for i := 0; i < len(tmp); i++ {
		tmp[i] = NULL
	}
	return tmp
}

func NewTrie() *Trie {
	t := &Trie{
		lefts:  makeArray(128),
		rights: makeArray(128),
		values: makeArray(128),
		size:   1,
	}
	return t
}

func (t *Trie) Add(p uint32, plen byte, key uint32) {
	var bit uint32 = IPV4_HIGH_BIT
	var mask uint32 = NULL << (32 - plen)
	var node uint32
	var next *uint32

	if len(t.lefts)-int(t.size) < int(plen) {
		tmp := makeArray(128)
		t.lefts = append(t.lefts, tmp...)
		t.rights = append(t.rights, tmp...)
		t.values = append(t.values, tmp...)
	}
	// ensure p is network address
	p &= mask

	for bit&mask != 0 {
		if p&bit != 0 {
			next = &t.rights[node]
		} else {
			next = &t.lefts[node]
		}
		if *next > t.size {
			*next = t.size
			t.size++
		}
		bit >>= 1
		node = *next
	}
	t.values[node] = key
}

func (t *Trie) Lookup(p uint32) uint32 {
	var bit uint32 = IPV4_HIGH_BIT
	var node, value uint32 = 0, NULL

	for node != NULL {
		if t.values[node] != NULL {
			value = t.values[node]
		}
		if p&bit != 0 {
			node = t.rights[node]
		} else {
			node = t.lefts[node]
		}
		bit >>= 1
	}
	return value
}

func (t *Trie) Match(p uint32) bool {
	var bit uint32 = IPV4_HIGH_BIT
	var node, value uint32 = 0, NULL

	for node != NULL {
		if t.values[node] != NULL {
			value = t.values[node]
		}
		if p&bit != 0 {
			node = t.rights[node]
		} else {
			node = t.lefts[node]
		}
		bit >>= 1
	}
	return value != NULL
}
