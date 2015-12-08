package ipatrie

import (
	"fmt"
)

const (
	FMASK = 0xFFffFFff
)

type Trie struct {
	root *TrieNode
	size uint32
	pool []TrieNode
}

type TrieNode struct {
	plen  byte
	key   bool
	addr  uint32
	child [2]*TrieNode
}

func ParseCIDR(s string) (p uint32, m byte, err error) {
	var sep byte
	for _, c := range []byte(s) {
		if c >= '0' && c <= '9' { // number
			m = m*10 + c - '0'
		} else if c == '.' || c == '/' {
			p, m = (p<<8)|uint32(m), 0
			sep += c
		} else { // exception
			err = fmt.Errorf("invalid syntax %s", c)
			return
		}
	}
	if sep != 185 {
		err = fmt.Errorf("invalid format")
	}
	return
}

// return 0 if supplied ipv6
func ParseIPv4(s string) uint32 {
	var a uint32
	var m byte
	for _, c := range []byte(s) {
		if c >= '0' && c <= '9' { // number
			m = m*10 + c - '0'
		} else if c == '.' {
			a, m = (a<<8)|uint32(m), 0
		} else if c == '[' { // v6
			return 0
		} else { // exception
			break
		}
	}
	return (a << 8) | uint32(m)
}

func NewTrie() *Trie {
	t := new(Trie)
	t.root = t.new_node(0, 0, false)
	return t
}

func (t *Trie) Size() int {
	return int(t.size)
}

func (t *Trie) __new_node(plen byte, paddr uint32, key bool) *TrieNode {
	t.size++
	return &TrieNode{
		addr: paddr,
		key:  key,
		plen: plen,
	}
}

func (t *Trie) new_node(plen byte, paddr uint32, key bool) *TrieNode {
	index := int(t.size) % 128
	if index == 0 {
		t.pool = make([]TrieNode, 128)
	}
	t.size++
	n := &t.pool[index]
	n.addr = paddr
	n.key = key
	n.plen = plen
	return n
}

func ipa_getbit(a uint32, pos byte) uint32 {
	return a & (0x80000000 >> pos)
}

func ipa_mkmask(n byte) uint32 {
	return FMASK << (32 - n)
}

func mask_addr(a uint32, plen byte) uint32 {
	return a & (FMASK << (32 - plen))
}

func ipa_pxlen(a, b uint32) byte {
	return 31 - u32_log2(a^b)
}

func b2u_shift(b bool, lsh byte) uint32 {
	if b {
		return 1 << lsh
	} else {
		return 0
	}
}

func u32_log2(v uint32) byte {
	/* The code from http://www-graphics.stanford.edu/~seander/bithacks.html */
	var r, shift uint32
	r = b2u_shift(v > 0xFFFF, 4)
	v >>= r

	shift = b2u_shift(v > 0xFF, 3)
	v >>= shift
	r |= shift

	shift = b2u_shift(v > 0xF, 2)
	v >>= shift
	r |= shift

	shift = b2u_shift(v > 0x3, 1)
	v >>= shift
	r |= shift

	r |= v >> 1
	return byte(r)
}

func attach_node(parent, child *TrieNode) {
	if ipa_getbit(child.addr, parent.plen) == 0 {
		parent.child[0] = child
	} else {
		parent.child[1] = child
	}
}

func (t *Trie) Insert(px uint32, plen byte) *TrieNode {
	var pmask, paddr, cmask uint32
	pmask = ipa_mkmask(plen)
	paddr = px & pmask
	var o, n *TrieNode = nil, t.root

	for n != nil {
		cmask = ipa_mkmask(n.plen) & pmask
		if paddr&cmask != n.addr&cmask {
			/* We are out of path - we have to add branching node 'b'
			   between node 'o' and node 'n', and attach new node 'a'
			   as the other child of 'b'. */
			blen := ipa_pxlen(paddr, n.addr)
			baddr := px & ipa_mkmask(blen)
			baccm := n.key && (blen >= 32)

			a := t.new_node(plen, paddr, true)
			b := t.new_node(blen, baddr, baccm)
			attach_node(o, b)
			attach_node(b, n)
			attach_node(b, a)
			return a
		}

		if plen < n.plen {
			/* We add new node 'a' between node 'o' and node 'n' */
			a := t.new_node(plen, paddr, true)
			attach_node(o, a)
			attach_node(a, n)
			return a
		}

		if plen == n.plen {
			/* We already found added node in trie. Just update accept mask */
			n.key = true
			return n
		}

		//n.accept = n.accept || (ipa_mkmask(n.plen)&1 == 1)
		if n.plen >= 32 {
			n.key = true
		}

		o = n
		if ipa_getbit(paddr, n.plen) == 0 {
			n = n.child[0]
		} else {
			n = n.child[1]
		}
	}
	/* We add new tail node 'a' after node 'o' */
	a := t.new_node(plen, paddr, true)
	attach_node(o, a)
	return a
}

func (t *Trie) Match(paddr uint32) bool {
	for n := t.root; n != nil; {
		if mask_addr(paddr, n.plen) == n.addr {
			/* Check key node */
			if n.key {
				return true
			}

			//	return false if 32 <= n.plen

			/* Choose children */
			if ipa_getbit(paddr, n.plen) == 0 {
				n = n.child[0]
			} else {
				n = n.child[1]
			}
		} else { /* We are out of path */
			return false
		}
	}
	return false
}
