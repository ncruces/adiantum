//go:build gc

package xchacha

import (
	"encoding/binary"

	"golang.org/x/sys/cpu"
)

func init() {
	useVX = cpu.S390X.HasVX
}

func initialize(state *[64]byte, key []byte, nonce *[16]byte) {
	initializeGeneric(state, key, nonce)

	if useVX {
		// Assembly wants state as *uint32 not *byte.
		for i := 0; i < 64; i += 4 {
			b := state[i:]
			v := binary.LittleEndian.Uint32(b)
			binary.BigEndian.PutUint32(b, v)
		}
	}
}

func xorKeyStream(dst, src []byte, block, state *[64]byte, rounds int) int {
	switch {
	case useVX:
		const bufSize = 256

		key := (*[32]byte)(state[16:48])
		counter := (*[4]byte)(state[48:52])
		nonce := (*[12]byte)(state[52:64])

		// Handle N full bufSize blocks.
		if full := len(src) &^ (bufSize - 1); full > 0 {
			xorKeyStreamVX(dst[:full], src[:full], key, nonce, counter, rounds)
			dst, src = dst[full:], src[full:]
		}

		// Handle a partial bufSize block.
		if len(src) > 0 {
			var buf [bufSize]byte
			copy(buf[:], src)
			xorKeyStreamVX(buf[:], buf[:], key, nonce, counter, rounds)
			copy(dst, buf[:])
		}

		return len(src)
	default:
		return xorKeyStreamGeneric(dst, src, block, state, rounds)
	}
}

//go:noescape
func xorKeyStreamVX(dst, src []byte, key *[32]byte, nonce *[12]byte, counter *[4]byte, rounds int)
