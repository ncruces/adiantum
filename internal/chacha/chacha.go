// Copyright (c) 2016 Andreas Auernhammer. All rights reserved.
// Use of this source code is governed by a license that can be
// found in the LICENSE file.

// Originally from:
// https://github.com/aead/chacha20/tree/master/chacha

// Package chacha implements some low-level functions of the
// ChaCha cipher family.
package chacha

import "errors"

const (
	// NonceSize is the size of the ChaCha20 nonce in bytes.
	NonceSize = 8

	// INonceSize is the size of the IETF-ChaCha20 nonce in bytes.
	INonceSize = 12

	// XNonceSize is the size of the XChaCha20 nonce in bytes.
	XNonceSize = 24

	// KeySize is the size of the key in bytes.
	KeySize = 32
)

var (
	useSSE2  bool
	useSSSE3 bool
	useAVX   bool
	useAVX2  bool
	useVX    bool
)

var (
	errKeySize      = errors.New("chacha20/chacha: bad key length")
	errInvalidNonce = errors.New("chacha20/chacha: bad nonce length")
)

func setup(state *[64]byte, nonce, key []byte) (err error) {
	if len(key) != KeySize {
		err = errKeySize
		return
	}
	var Nonce [16]byte
	switch len(nonce) {
	case NonceSize:
		copy(Nonce[8:], nonce)
		initialize(state, key, &Nonce)
	case INonceSize:
		copy(Nonce[4:], nonce)
		initialize(state, key, &Nonce)
	case XNonceSize:
		var tmpKey [32]byte
		var hNonce [16]byte

		copy(hNonce[:], nonce[:16])
		copy(tmpKey[:], key)
		HChaCha20(&tmpKey, &hNonce, &tmpKey)
		copy(Nonce[8:], nonce[16:])
		initialize(state, tmpKey[:], &Nonce)
	default:
		err = errInvalidNonce
	}
	return
}

// XORKeyStream crypts bytes from src to dst using the given nonce and key.
// The length of the nonce determinds the version of ChaCha20:
// - NonceSize:  ChaCha20/r with a 64 bit nonce and a 2^64 * 64 byte period.
// - INonceSize: ChaCha20/r as defined in RFC 7539 and a 2^32 * 64 byte period.
// - XNonceSize: XChaCha20/r with a 192 bit nonce and a 2^64 * 64 byte period.
// The rounds argument specifies the number of rounds performed for keystream
// generation - valid values are 8, 12 or 20. The src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) this function panics.
// If the nonce is neither 64, 96 nor 192 bits long, this function panics.
func XORKeyStream(dst, src, nonce, key []byte, rounds int) {
	if rounds != 20 && rounds != 12 && rounds != 8 {
		panic("chacha20/chacha: bad number of rounds")
	}
	if len(dst) < len(src) {
		panic("chacha20/chacha: dst buffer is to small")
	}
	if len(nonce) == INonceSize && uint64(len(src)) > (1<<38) {
		panic("chacha20/chacha: src is too large")
	}

	var block, state [64]byte
	if err := setup(&state, nonce, key); err != nil {
		panic(err)
	}
	xorKeyStream(dst, src, &block, &state, rounds)
}

// HChaCha20 generates 32 pseudo-random bytes from a 128 bit nonce and a 256 bit secret key.
// It can be used as a key-derivation-function (KDF).
func HChaCha20(out *[32]byte, nonce *[16]byte, key *[32]byte) { hChaCha20(out, nonce, key) }